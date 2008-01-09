/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2008 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <munge.h>
#include <stdlib.h>
#include <string.h>
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
#include "timer.h"
#include "version.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void handle_signals (void);
static void hup_handler (int signum);
static void exit_handler (int signum);
static void segv_handler (int signum);
static int  daemonize_init (char *progname);
static void daemonize_fini (int fd);
static void write_pidfile (const char *pidfile, int got_force);
static void open_logfile (const char *logfile, int priority, int got_force);
static void sock_create (conf_t conf);
static void sock_destroy (conf_t conf);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

int done = 0;                           /* global flag set true for exit     */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    int fd = -1;
    int priority = LOG_INFO;

#ifndef NDEBUG
    priority = LOG_DEBUG;
#endif /* NDEBUG */
    log_open_file (stderr, argv[0], priority, LOG_OPT_PRIORITY);

    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    auth_recv_init (conf->auth_server_dir, conf->auth_client_dir,
        conf->got_force);

    if (!conf->got_foreground) {
        fd = daemonize_init (argv[0]);
        open_logfile (conf->logfile_name, priority, conf->got_force);
    }
    handle_signals ();
    lookup_ip_addr (conf);
    write_pidfile (conf->pidfile_name, conf->got_force);

    crypto_init ();
    if (random_init (conf->seed_name) < 0) {
        if (conf->seed_name) {
            free (conf->seed_name);
            conf->seed_name = NULL;
        }
    }
    create_subkeys (conf);
    conf->gids = gids_create (conf->gids_interval, conf->got_group_stat);
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
handle_signals (void)
{
    if (posignal (SIGHUP, hup_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGHUP);
    }
    if (posignal (SIGINT, exit_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGINT);
    }
    if (posignal (SIGTERM, exit_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGTERM);
    }
    if (posignal (SIGSEGV, segv_handler) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGSEGV);
    }
    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);
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
        done = 1;
        log_msg (LOG_NOTICE, "Exiting on signal=%d", signum);
    }
    return;
}


static void
segv_handler (int signum)
{
    log_err (EMUNGE_SNAFU, LOG_CRIT,
        "Exiting on signal=%d (segmentation violation)", signum);
    assert (1);                         /* not reached */
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
    struct rlimit limit;
    int           fds [2];
    pid_t         pid;
    int           n;
    signed char   priority;
    char          ebuf [1024];

    /*  Clear file mode creation mask.
     */
    umask (0);

    /*  Disable creation of core files.
     */
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if (setrlimit (RLIMIT_CORE, &limit) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to prevent creation of core file");
    }
    /*  Create pipe for IPC so parent process will wait to terminate until
     *    signaled by grandchild process.  This allows messages written to
     *    stdout/stderr by the grandchild to be properly displayed before
     *    the parent process returns control to the shell.
     */
    if (pipe (fds) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to create daemon pipe");
    }
    /*  Set the fd used by log_err() to return status back to the parent.
     */
    log_set_err_pipe (fds[1]);

    /*  Automatically background the process and
     *    ensure child is not a process group leader.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to create child process");
    }
    else if (pid > 0) {
        log_set_err_pipe (-1);
        if (close (fds[1]) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close write-pipe in parent process");
        }
        if ((n = read (fds[0], &priority, sizeof (priority))) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to read status from grandchild process");
        }
        if ((n > 0) && (priority >= 0)) {
            if ((n = read (fds[0], ebuf, sizeof (ebuf))) < 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to read err msg from grandchild process");
            }
            if ((n > 0) && (ebuf[0] != '\0')) {
                log_open_file (stderr, progname, priority, LOG_OPT_PRIORITY);
                log_msg (priority, "%s", ebuf);
            }
            exit (1);
        }
        exit (0);
    }
    if (close (fds[0]) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close read-pipe in child process");
    }
    /*  Become a session leader and process group leader
     *    with no controlling tty.
     */
    if (setsid () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to disassociate controlling tty");
    }
    /*  Ignore SIGHUP to keep child from terminating when
     *    the session leader (ie, the parent) terminates.
     */
    if (posignal (SIGHUP, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGHUP);
    }
    /*  Abdicate session leader position in order to guarantee
     *    daemon cannot automatically re-acquire a controlling tty.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to create grandchild process");
    }
    else if (pid > 0) {
        exit (0);
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
            "Unable to change to root directory");
    }
    /*  Discard data to/from stdin, stdout, and stderr.
     */
    if ((dev_null = open ("/dev/null", O_RDWR)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to open \"/dev/null\"");
    }
    if (dup2 (dev_null, STDIN_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to dup \"/dev/null\" onto stdin");
    }
    if (dup2 (dev_null, STDOUT_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to dup \"/dev/null\" onto stdout");
    }
    if (dup2 (dev_null, STDERR_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to dup \"/dev/null\" onto stderr");
    }
    if (close (dev_null) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to close \"/dev/null\"");
    }
    /*  Clear the fd used by log_err() to return status back to the parent.
     */
    log_set_err_pipe (-1);
    /*
     *  Signal grandparent process to terminate.
     */
    if ((fd >= 0) && (close (fd) < 0)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close write-pipe in grandchild process");
    }
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
            "Cannot determine dirname of pidfile \"%s\"", pidfile);
    }
    n = path_is_secure (piddir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Cannot check pidfile dir \"%s\": %s", piddir, ebuf);
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
        log_msg (LOG_WARNING, "Unable to open pidfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else if (fprintf (fp, "%d\n", (int) getpid ()) == EOF) {
        log_msg (LOG_WARNING, "Unable to write to pidfile \"%s\": %s",
            pidfile, strerror (errno));
        (void) fclose (fp);
    }
    else if (fclose (fp) == EOF) {
        log_msg (LOG_WARNING, "Unable to close pidfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else {
        return;                         /* success */
    }
    (void) unlink (pidfile);
    return;                             /* failure */
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
                "Cannot check logfile \"%s\"", logfile);
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
                    "Logfile is insecure: \"%s\" should be owned by uid=%u",
                    logfile, (unsigned) geteuid ());
            else
                log_msg (LOG_WARNING,
                    "Logfile is insecure: \"%s\" should be owned by uid=%u",
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
            "Cannot determine dirname of logfile \"%s\"", logfile);
    }
    n = path_is_secure (logdir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Cannot check logfile dir \"%s\": %s", logdir, ebuf);
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
            "Unable to open logfile \"%s\"", logfile);
    }
    log_open_file (fp, NULL, priority,
        LOG_OPT_JUSTIFY | LOG_OPT_PRIORITY | LOG_OPT_TIMESTAMP);
    return;
}


static void
sock_create (conf_t conf)
{
    char                sockdir [PATH_MAX];
    char                ebuf [1024];
    int                 n;
    int                 got_symlink;
    struct stat         st;
    mode_t              mask;
    int                 sd;
    struct sockaddr_un  addr;

    assert (conf != NULL);

    if ((conf->socket_name == NULL) || (*conf->socket_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "MUNGE socket has no name");
    }
    /*  Ensure socket dir is secure against modification by others.
     */
    if (path_dirname (conf->socket_name, sockdir, sizeof (sockdir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Cannot determine dirname of socket \"%s\"", conf->socket_name);
    }
    n = path_is_secure (sockdir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Cannot check socket dir \"%s\": %s", sockdir, ebuf);
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
            "Cannot check socket dir \"%s\": %s", sockdir, ebuf);
    }
    else if ((n == 0) && (!conf->got_force)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Socket is inaccessible: %s", ebuf);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Socket is inaccessible: %s", ebuf);
    }
    /*  Check for an existing socket.
     */
    if (conf->got_force) {
        (void) unlink (conf->socket_name);
    }
    got_symlink = (lstat (conf->socket_name, &st) == 0)
        ? S_ISLNK (st.st_mode) : 0;
    n = stat (conf->socket_name, &st);
    if ((n < 0) && (errno != ENOENT)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Cannot check existing socket \"%s\"", conf->socket_name);
    }
    else if (n == 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Found existing socket \"%s\"", conf->socket_name);
    }
    else if (got_symlink) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Found dangling symlink to socket \"%s\"", conf->socket_name);
    }
    /*  Create the socket, ensuring everyone has access to it.
     */
    mask = umask (0);

    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Cannot create socket");
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, conf->socket_name, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Exceeded maximum length of socket pathname");
    }
    if (bind (sd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Cannot bind to \"%s\"", conf->socket_name);
    }
    umask (mask);

    if (listen (sd, MUNGE_SOCKET_BACKLOG) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Cannot listen to \"%s\"", conf->socket_name);
    }
    conf->ld = sd;
    return;
}


static void
sock_destroy (conf_t conf)
{
    assert (conf != NULL);
    assert (conf->ld >= 0);
    assert (conf->socket_name != NULL);

    if (conf->socket_name) {
        if (unlink (conf->socket_name) < 0) {
            log_msg (LOG_WARNING, "Unable to unlink \"%s\": %s",
                conf->socket_name, strerror (errno));
        }
    }
    if (conf->ld >= 0) {
        if (close (conf->ld) < 0) {
            log_msg (LOG_WARNING, "Unable to close \"%s\": %s",
                conf->ld, strerror (errno));
        }
        conf->ld = -1;
    }
    return;
}
