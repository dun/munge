/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2013 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://munge.googlecode.com/>.
 *
 *  MUNGE is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation, either version 3 of the License, or (at your option)
 *  any later version.  Additionally for the MUNGE library (libmunge), you
 *  can redistribute it and/or modify it under the terms of the GNU Lesser
 *  General Public License as published by the Free Software Foundation,
 *  either version 3 of the License, or (at your option) any later version.
 *
 *  MUNGE is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  and GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  and GNU Lesser General Public License along with MUNGE.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <munge.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>                   /* include before resource.h for bsd */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "auth_recv.h"
#include "common.h"
#include "conf.h"
#include "crypto.h"
#include "gids.h"
#include "job.h"
#include "log.h"
#include "missing.h"
#include "munge_defs.h"
#include "path.h"
#include "posignal.h"
#include "random.h"
#include "replay.h"
#include "str.h"
#include "timer.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void disable_core_dumps (void);
static int daemonize_init (char *progname);
static void daemonize_fini (int fd);
static void open_logfile (const char *logfile, int priority, int got_force);
static void handle_signals (void);
static void hup_handler (int signum);
static void exit_handler (int signum);
static void segv_handler (int signum);
static void write_pidfile (const char *pidfile, int got_force);
static void sock_create (conf_t conf);
static void sock_lock (conf_t conf);
static int set_file_lock (int fd);
static pid_t is_file_locked (int fd);
static void sock_destroy (conf_t conf);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

volatile sig_atomic_t done = 0;         /* global flag set true for exit     */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    int   fd = -1;
    char *log_identity = argv[0];
    int   log_priority = LOG_INFO;
    int   log_options = LOG_OPT_PRIORITY;

#ifndef NDEBUG
    log_priority = LOG_DEBUG;
    log_options |= LOG_OPT_TIMESTAMP;
#endif /* NDEBUG */
    log_open_file (stderr, log_identity, log_priority, log_options);

    disable_core_dumps ();
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    auth_recv_init (conf->auth_server_dir, conf->auth_client_dir,
        conf->got_force);

    if (!conf->got_foreground) {
        fd = daemonize_init (argv[0]);
        if (conf->got_syslog) {
            log_open_file (NULL, NULL, 0, 0);
            log_open_syslog (log_identity, LOG_DAEMON);
        }
        else {
            open_logfile (conf->logfile_name, log_priority, conf->got_force);
        }
    }
    handle_signals ();
    lookup_ip_addr (conf);
    write_pidfile (conf->pidfile_name, conf->got_force);

    if (conf->got_mlockall){
#ifdef _POSIX_MEMLOCK
        if (mlockall(MCL_CURRENT|MCL_FUTURE) < 0) {
            log_msg (LOG_ERR, "%s (pid %d) could not lock pages",
                     META_ALIAS, (int) getpid ());
        }
#else
        log_msg (LOG_ERR, "%s (pid %d) does not appear to have mlockall()",
                     META_ALIAS, (int) getpid ());
#endif /* _POSIX_MEMLOCK */
    }

    crypto_init ();
    if (random_init (conf->seed_name) < 0) {
        if (conf->seed_name) {
            free (conf->seed_name);
            conf->seed_name = NULL;
        }
    }
    create_subkeys (conf);
    conf->gids = gids_create (conf->gids_update_secs, conf->got_group_stat);
    replay_init ();
    timer_init ();
    sock_create (conf);

    if (!conf->got_foreground) {
        daemonize_fini (fd);
    }
    log_msg (LOG_NOTICE, "Starting %s daemon (pid %d)",
        META_ALIAS, (int) getpid ());

    job_accept (conf);

    sock_destroy (conf);
    timer_fini ();
    replay_fini ();
    gids_destroy (conf->gids);
    random_fini (conf->seed_name);
    crypto_fini ();
    destroy_conf (conf);

    log_msg (LOG_NOTICE, "Stopping %s daemon (pid %d)",
        META_ALIAS, (int) getpid ());

    exit (EMUNGE_SUCCESS);
}


static void
disable_core_dumps (void)
{
/*  Disable creation of core dump files.
 */
#ifdef NDEBUG
    struct rlimit limit;

    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if (setrlimit (RLIMIT_CORE, &limit) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to disable core dumps");
    }
#endif /* NDEBUG */
    return;
}


static int
daemonize_init (char *progname)
{
/*  Begins the daemonization of the process.
 *  Despite the fact that this routine backgrounds the process, control
 *    will not be returned to the shell until daemonize_fini() is called.
 *  Returns an 'fd' to pass to daemonize_fini() to complete the daemonization.
 */
    int         fds [2];
    pid_t       pid;
    int         n;
    signed char priority;
    char        ebuf [1024];

    /*  Clear file mode creation mask.
     */
    umask (0);

    /*  Create pipe for IPC so parent process will wait to terminate until
     *    signaled by grandchild process.  This allows messages written to
     *    stdout/stderr by the grandchild to be properly displayed before
     *    the parent process returns control to the shell.
     */
    if (pipe (fds) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create daemon pipe");
    }
    /*  Set the fd used by log_err() to return status back to the parent.
     */
    log_set_err_pipe (fds[1]);

    /*  Automatically background the process and
     *    ensure child is not a process group leader.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create child process");
    }
    else if (pid > 0) {
        log_set_err_pipe (-1);
        if (close (fds[1]) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to close write-pipe in parent process");
        }
        if ((n = read (fds[0], &priority, sizeof (priority))) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to read status from grandchild process");
        }
        if ((n > 0) && (priority >= 0)) {
            if ((n = read (fds[0], ebuf, sizeof (ebuf))) < 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to read err msg from grandchild process");
            }
            if ((n > 0) && (ebuf[0] != '\0')) {
                log_open_file (stderr, progname, priority, LOG_OPT_PRIORITY);
                log_msg (priority, "%s", ebuf);
            }
            exit (EXIT_FAILURE);
        }
        exit (EXIT_SUCCESS);
    }
    if (close (fds[0]) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to close read-pipe in child process");
    }
    /*  Become a session leader and process group leader
     *    with no controlling tty.
     */
    if (setsid () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to disassociate controlling tty");
    }
    /*  Ignore SIGHUP to keep child from terminating when
     *    the session leader (ie, the parent) terminates.
     */
    if (posignal (SIGHUP, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to ignore signal=%d", SIGHUP);
    }
    /*  Abdicate session leader position in order to guarantee
     *    daemon cannot automatically re-acquire a controlling tty.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to create grandchild process");
    }
    else if (pid > 0) {
        exit (EXIT_SUCCESS);
    }
    return (fds[1]);
}


static void
daemonize_fini (int fd)
{
/*  Completes the daemonization of the process,
 *    where 'fd' is the file descriptor returned by daemonize_init().
 */
    int dev_null;

    /*  Ensure process does not keep a directory in use.
     *    Avoid relative pathnames from this point on!
     */
    if (chdir ("/") < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to change to root directory");
    }
    /*  Discard data to/from stdin, stdout, and stderr.
     */
    if ((dev_null = open ("/dev/null", O_RDWR)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to open \"/dev/null\"");
    }
    if (dup2 (dev_null, STDIN_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to dup \"/dev/null\" onto stdin");
    }
    if (dup2 (dev_null, STDOUT_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to dup \"/dev/null\" onto stdout");
    }
    if (dup2 (dev_null, STDERR_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to dup \"/dev/null\" onto stderr");
    }
    if (close (dev_null) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close \"/dev/null\"");
    }
    /*  Clear the fd used by log_err() to return status back to the parent.
     */
    log_set_err_pipe (-1);
    /*
     *  Signal grandparent process to terminate.
     */
    if ((fd >= 0) && (close (fd) < 0)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to close write-pipe in grandchild process");
    }
    return;
}


static void
open_logfile (const char *logfile, int priority, int got_force)
{
    int          got_symlink;
    struct stat  st;
    int          n;
    char         logdir [PATH_MAX];
    char         ebuf [1024];
    mode_t       mask;
    FILE        *fp;

    /*  Check file permissions and whatnot.
     */
    got_symlink = (lstat (logfile, &st) == 0) ? S_ISLNK (st.st_mode) : 0;

    if (((n = stat (logfile, &st)) < 0) && (errno == ENOENT)) {
        if (!got_symlink) {
            ; /* A missing logfile is not considered an error. */
        }
        else if (!got_force) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Logfile is insecure: \"%s\" should be a regular file",
                logfile);
        }
        else {
            log_msg (LOG_WARNING,
                "Logfile is insecure: \"%s\" should not be a symlink",
                logfile);
        }
    }
    else {
        if (n < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to check logfile \"%s\"", logfile);
        }
        if (!S_ISREG (st.st_mode) || got_symlink) {
            if (!got_force || !got_symlink)
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Logfile is insecure: \"%s\" should be a regular file",
                    logfile);
            else
                log_msg (LOG_WARNING,
                    "Logfile is insecure: \"%s\" should not be a symlink",
                    logfile);
        }
        if (st.st_uid != geteuid ()) {
            if (!got_force)
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Logfile is insecure: \"%s\" should be owned by UID %u",
                    logfile, (unsigned) geteuid ());
            else
                log_msg (LOG_WARNING,
                    "Logfile is insecure: \"%s\" should be owned by UID %u",
                    logfile, (unsigned) geteuid ());
        }
        if (st.st_mode & (S_IWGRP | S_IWOTH)) {
            if (!got_force)
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Logfile is insecure: \"%s\" should not be writable "
                    "by group or world", logfile);
            else
                log_msg (LOG_WARNING,
                    "Logfile is insecure: \"%s\" should not be writable "
                    "by group or world", logfile);
        }
    }
    /*  Ensure logfile dir is secure against modification by others.
     */
    if (path_dirname (logfile, logdir, sizeof (logdir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of logfile \"%s\"", logfile);
    }
    n = path_is_secure (logdir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check logfile dir \"%s\": %s", logdir, ebuf);
    }
    else if ((n == 0) && (!got_force)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Logfile is insecure: %s", ebuf);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Logfile is insecure: %s", ebuf);
    }
    /*  Protect logfile against unauthorized access by removing write-access
     *    from group and all access from other.
     */
    mask = umask (0);
    umask (mask | 027);
    fp = fopen (logfile, "a");
    umask (mask);

    if (!fp) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to open logfile \"%s\"", logfile);
    }
    log_open_file (fp, NULL, priority,
        LOG_OPT_JUSTIFY | LOG_OPT_PRIORITY | LOG_OPT_TIMESTAMP);
    return;
}


static void
handle_signals (void)
{
    if (posignal (SIGHUP, hup_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to handle signal=%d", SIGHUP);
    }
    if (posignal (SIGINT, exit_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to handle signal=%d", SIGINT);
    }
    if (posignal (SIGTERM, exit_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to handle signal=%d", SIGTERM);
    }
    if (posignal (SIGSEGV, segv_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to handle signal=%d", SIGSEGV);
    }
    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to ignore signal=%d", SIGPIPE);
    }
    return;
}


static void
hup_handler (int signum)
{
    if (conf) {
        gids_update (conf->gids);
    }
    return;
}


static void
exit_handler (int signum)
{
    if (!done) {
        done = signum;
    }
    return;
}


static void
segv_handler (int signum)
{
    log_err (EMUNGE_SNAFU, LOG_CRIT,
        "Exiting on signal=%d (segfault)", signum);
    assert (1);                         /* not reached */
    return;
}


static void
write_pidfile (const char *pidfile, int got_force)
{
/*  Creates the specified pidfile.
 *  The pidfile must be created after the daemon has finished forking.
 */
    char    piddir [PATH_MAX];
    char    ebuf [1024];
    int     n;
    mode_t  mask;
    FILE   *fp;

    assert (pidfile != NULL);

    /*  The pidfile must be specified with an absolute pathname; o/w, the
     *    unlink() call in destroy_conf() will fail because the daemon has
     *    chdir()'d.
     */
    if (pidfile[0] != '/') {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Pidfile \"%s\" requires an absolute path", pidfile);
    }
    /*  Ensure pidfile dir is secure against modification by others.
     */
    if (path_dirname (pidfile, piddir, sizeof (piddir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of pidfile \"%s\"", pidfile);
    }
    n = path_is_secure (piddir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check pidfile dir \"%s\": %s", piddir, ebuf);
    }
    else if ((n == 0) && (!got_force)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Pidfile is insecure: %s", ebuf);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Pidfile is insecure: %s", ebuf);
    }
    /*  Protect pidfile against unauthorized access by removing write-access
     *    from group and other.
     */
    mask = umask (0);
    umask (mask | 022);
    (void) unlink (pidfile);
    fp = fopen (pidfile, "w");
    umask (mask);
    /*
     *  An error in creating the pidfile is not considered fatal.
     */
    if (!fp) {
        log_msg (LOG_WARNING, "Failed to open pidfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else if (fprintf (fp, "%d\n", (int) getpid ()) == EOF) {
        log_msg (LOG_WARNING, "Failed to write to pidfile \"%s\": %s",
            pidfile, strerror (errno));
        (void) fclose (fp);
    }
    else if (fclose (fp) == EOF) {
        log_msg (LOG_WARNING, "Failed to close pidfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else {
        return;                         /* success */
    }
    (void) unlink (pidfile);
    return;                             /* failure */
}


static void
sock_create (conf_t conf)
{
    char                sockdir [PATH_MAX];
    char                ebuf [1024];
    int                 n;
    int                 sd;
    struct sockaddr_un  addr;
    mode_t              mask;
    int                 rv;

    assert (conf != NULL);

    if ((conf->socket_name == NULL) || (*conf->socket_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "MUNGE socket name is undefined");
    }
    /*  Ensure socket dir is secure against modification by others.
     */
    if (path_dirname (conf->socket_name, sockdir, sizeof (sockdir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of socket \"%s\"", conf->socket_name);
    }
    n = path_is_secure (sockdir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check socket dir \"%s\": %s", sockdir, ebuf);
    }
    else if ((n == 0) && (!conf->got_force)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Socket is insecure: %s", ebuf);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Socket is insecure: %s", ebuf);
    }
    /*  Ensure socket dir is accessible by all.
     */
    n = path_is_accessible (sockdir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check socket dir \"%s\": %s", sockdir, ebuf);
    }
    else if ((n == 0) && (!conf->got_force)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Socket is inaccessible: %s", ebuf);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Socket is inaccessible: %s", ebuf);
    }
    /*  Create lockfile for exclusive access to the socket.
     */
    sock_lock (conf);
    /*
     *  Create socket for communicating with clients.
     */
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create socket");
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, conf->socket_name, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Exceeded maximum length of socket pathname");
    }
    /*  Ensure socket is accessible by all.
     */
    mask = umask (0);
    rv = bind (sd, (struct sockaddr *) &addr, sizeof (addr));
    umask (mask);

    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to bind \"%s\"", conf->socket_name);
    }
    if (listen (sd, MUNGE_SOCKET_BACKLOG) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to listen on \"%s\"", conf->socket_name);
    }
    conf->ld = sd;
    return;
}


static void
sock_lock (conf_t conf)
{
/*  Ensures exclusive access to the unix domain socket.
 */
    struct stat  st;
    mode_t       mask;
    int          rv;

    assert (conf != NULL);
    assert (conf->lockfile_name == NULL);
    assert (conf->lockfile_fd == -1);
    assert (conf->socket_name != NULL);

    if (!(conf->lockfile_name = strdupf ("%s.lock", conf->socket_name))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to create lockfile string");
    }
    if (conf->got_force) {
        if ((unlink (conf->lockfile_name) < 0) && (errno != ENOENT)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to remove \"%s\"",
                conf->lockfile_name);
        }
    }
    else if (lstat (conf->lockfile_name, &st) < 0) {
        if (errno != ENOENT) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to stat \"%s\"",
                conf->lockfile_name);
        }
    }
    else if (!S_ISREG(st.st_mode)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Lockfile is suspicious: \"%s\" should be a regular file",
            conf->lockfile_name);
    }
    else if (st.st_uid != geteuid()) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Lockfile is suspicious: \"%s\" should be owned by UID %u",
            conf->lockfile_name, (unsigned) geteuid());
    }
    else if ((st.st_mode & 07777) != S_IWUSR) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Lockfile is suspicious: \"%s\" should be writable only by user",
            conf->lockfile_name);
    }
    mask = umask (0);
    conf->lockfile_fd = creat (conf->lockfile_name, S_IWUSR);
    umask (mask);

    if (conf->lockfile_fd < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to create \"%s\"", conf->lockfile_name);
    }
    if ((rv = set_file_lock (conf->lockfile_fd)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to lock \"%s\"", conf->lockfile_name);
    }
    if (rv > 0) {

        pid_t pid = is_file_locked (conf->lockfile_fd);

        if (pid < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to test lock \"%s\"", conf->lockfile_name);
        }
        else if (pid > 0) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Found pid %d bound to socket \"%s\"", pid, conf->socket_name);
        }
        else {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Found inconsistent state for lock \"%s\"",
                conf->lockfile_name);
        }
    }
    if (unlink (conf->socket_name) == 0) {
        log_msg (LOG_INFO, "Removed existing socket \"%s\"",
            conf->socket_name);
    }
    else if (errno != ENOENT) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to remove \"%s\"",
            conf->socket_name);
    }
    return;
}


static int
set_file_lock (int fd)
{
/*  Sets an exclusive advisory lock on the open file descriptor 'fd'.
 *  Returns 0 on success, 1 if a conflicting lock is held by another process,
 *    or -1 on error (with errno set).
 */
    struct flock  fl;
    int           rv;

    if (fd < 0) {
        errno = EBADF;
        return (-1);
    }
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rv = fcntl (fd, F_SETLK, &fl);
    if (rv < 0) {
        if ((errno == EACCES) || (errno == EAGAIN)) {
            return (1);
        }
        return (-1);
    }
    return (0);
}


static pid_t
is_file_locked (int fd)
{
/*  Tests whether an exclusive advisory lock could be obtained for the open
 *    file descriptor 'fd'.
 *  Returns 0 if the file is not locked, >0 for the pid of another process
 *    holding a conflicting lock, or -1 on error (with errno set).
 */
    struct flock  fl;
    int           rv;

    if (fd < 0) {
        errno = EBADF;
        return (-1);
    }
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rv = fcntl (fd, F_GETLK, &fl);
    if (rv < 0) {
        return (-1);
    }
    if (fl.l_type == F_UNLCK) {
        return (0);
    }
    return (fl.l_pid);
}


static void
sock_destroy (conf_t conf)
{
    assert (conf != NULL);
    assert (conf->ld >= 0);
    assert (conf->socket_name != NULL);

    if (conf->socket_name) {
        if (unlink (conf->socket_name) < 0) {
            log_msg (LOG_WARNING, "Failed to remove \"%s\": %s",
                conf->socket_name, strerror (errno));
        }
    }
    if (conf->ld >= 0) {
        if (close (conf->ld) < 0) {
            log_msg (LOG_WARNING, "Failed to close \"%s\": %s",
                conf->ld, strerror (errno));
        }
        conf->ld = -1;
    }
    if (conf->lockfile_name) {
        if (unlink (conf->lockfile_name) < 0) {
            log_msg (LOG_WARNING, "Failed to remove \"%s\": %s",
                conf->lockfile_name, strerror (errno));
        }
    }
    if (conf->lockfile_fd >= 0) {
        if (close (conf->lockfile_fd) < 0) {
            log_msg (LOG_WARNING, "Failed to close \"%s\": %s",
                conf->lockfile_fd, strerror (errno));
        }
        conf->lockfile_fd = -1;
    }
    return;
}
