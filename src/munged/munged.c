/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2022 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://dun.github.io/munge/>.
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
#if HAVE_MLOCKALL
#include <sys/mman.h>
#endif /* HAVE_MLOCKALL */
#include <sys/time.h>                   /* include before resource.h for bsd */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "auth_recv.h"
#include "cipher.h"
#include "common.h"
#include "conf.h"
#include "crypto.h"
#include "daemonpipe.h"
#include "gids.h"
#include "hash.h"
#include "job.h"
#include "lock.h"
#include "log.h"
#include "md.h"
#include "missing.h"
#include "munge_defs.h"
#include "path.h"
#include "random.h"
#include "replay.h"
#include "str.h"
#include "timer.h"
#include "xsignal.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void disable_core_dumps (void);
static void daemonize_init (char *progname, conf_t conf);
static void daemonize_fini (void);
static void open_logfile (const char *logfile, int priority, int got_force);
static void handle_signals (void);
static void sig_handler (int sig);
static void write_pidfile (const char *pidfile, int got_force);
static void lock_memory (void);
static void sock_create (conf_t conf);
static void sock_destroy (conf_t conf);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

volatile sig_atomic_t got_reconfig = 0;     /* signum if HUP received        */
volatile sig_atomic_t got_terminate = 0;    /* signum if INT/TERM received   */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
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
    process_conf (conf);
    auth_recv_init (conf->auth_server_dir, conf->auth_client_dir,
        conf->got_force);

    if (!conf->got_foreground) {
        daemonize_init (argv[0], conf);
        if (conf->got_syslog) {
            log_close_file ();
            log_open_syslog (log_identity, LOG_DAEMON);
        }
        else {
            open_logfile (conf->logfile_name, log_priority, conf->got_force);
        }
    }
    log_msg (LOG_NOTICE, "Starting %s-%s daemon (pid %d)",
        PACKAGE, VERSION, (int) getpid ());
    handle_signals ();
    write_origin_addr (conf);
    if (conf->got_mlockall) {
        lock_memory ();
    }
    crypto_init ();
    cipher_init_subsystem ();
    md_init_subsystem ();
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
    write_pidfile (conf->pidfile_name, conf->got_force);

    if (!conf->got_foreground) {
        daemonize_fini ();
    }
    job_accept (conf);

    sock_destroy (conf);
    timer_fini ();
    replay_fini ();
    gids_destroy (conf->gids);
    hash_drop_memory ();
    random_fini (conf->seed_name);
    crypto_fini ();
    destroy_conf (conf, 1);

    log_msg (LOG_NOTICE, "Stopping %s-%s daemon (pid %d)",
        PACKAGE, VERSION, (int) getpid ());
    log_close_all ();

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


static void
daemonize_init (char *progname, conf_t conf)
{
/*  Begins the daemonization of the process.
 *  Despite the fact that this routine backgrounds the process, control
 *    will not be returned to the shell until daemonize_fini() is called.
 */
    pid_t pid;
    int   status;
    int   priority;
    char  buf [1024];

    /*  Clear file mode creation mask.
     */
    umask (0);

    /*  Create a daemonpipe to have the parent process wait until signaled by
     *    its double-forked grandchild process that startup is complete.
     */
    if (daemonpipe_create () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create daemonpipe");
    }
    /*  Automatically background the process and
     *    ensure child process is not a process group leader.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to fork child process");
    }
    else if (pid > 0) {
        /*
         *  Parent process waits for notification that startup is complete
         *    before exiting.
         */
        if (daemonpipe_close_writes () < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to close write-end of daemonpipe");
        }
        if (daemonpipe_read (&status, &priority, buf, sizeof (buf)) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to read from daemonpipe");
        }
        if (status != 0) {
            if ((priority >= 0) && (buf[0] != '\0')) {
                log_msg (priority, "%s", buf);
            }
            exit (EXIT_FAILURE);
        }
        destroy_conf (conf, 0);
        log_close_all ();
        exit (EXIT_SUCCESS);
    }
    /*  Child process continues.
     */
    if (daemonpipe_close_reads () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to close read-end of daemonpipe");
    }
    /*  Become a session leader and process group leader
     *    with no controlling tty.
     */
    if (setsid () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to disassociate controlling tty");
    }
    /*  Ignore SIGHUP to keep child process from terminating when
     *    the session leader (i.e., the parent proces) terminates.
     */
    xsignal_ignore (SIGHUP);

    /*  Abdicate session leader position to ensure the daemon cannot
     *    automatically re-acquire a controlling tty.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to fork grandchild process");
    }
    else if (pid > 0) {
        destroy_conf (conf, 0);
        log_close_all ();
        exit (EXIT_SUCCESS);
    }
    /*  Grandchild process continues.
     */
    return;
}


static void
daemonize_fini (void)
{
/*  Completes the daemonization of the process.
 */
    int dev_null;

    /*  Ensure process does not keep a directory in use.
     *    Avoid relative pathnames from this point on!
     */
    if (chdir ("/") < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to change CWD to root directory");
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
    if ((dev_null > STDERR_FILENO) && (close (dev_null)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close \"/dev/null\"");
    }
    /*  Signal parent process to exit now that startup is complete.
     *  The daemonpipe_write() below is not strictly necessary since
     *    daemonpipe_close_writes() closes the daemonpipe which will cause
     *    daemonpipe_read() to read an EOF.
     */
    if (daemonpipe_write (0, 0, NULL) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to signal parent process that startup is complete");
    }
    if (daemonpipe_close_writes () < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to close write-end of daemonpipe");
    }
    return;
}


static void
open_logfile (const char *logfile, int priority, int got_force)
{
    int          is_symlink;
    int          is_missing;
    struct stat  st;
    int          rv;
    char         logdir [PATH_MAX];
    char         ebuf [1024];
    mode_t       mask;
    FILE        *fp;

    if ((logfile == NULL) || (*logfile == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Logfile name is undefined");
    }
    is_symlink = (lstat (logfile, &st) == 0) ? S_ISLNK (st.st_mode) : 0;
    if (is_symlink) {
        log_err_or_warn (got_force,
            "Logfile is insecure: \"%s\" should not be a symbolic link",
            logfile);
    }
    rv = stat (logfile, &st);
    is_missing = (rv < 0) && (errno == ENOENT);

    if (!is_missing) {
        if (rv < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to check logfile \"%s\"", logfile);
        }
        if (!S_ISREG (st.st_mode)) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Logfile is insecure: \"%s\" must be a regular file "
                "(type=%07o)", logfile, (st.st_mode & S_IFMT));
        }
        if (st.st_uid != geteuid ()) {
            log_err_or_warn (got_force,
                "Logfile is insecure: \"%s\" should be owned by UID %u "
                "instead of UID %u", logfile, (unsigned) geteuid (),
                (unsigned) st.st_uid);
        }
        if (st.st_mode & S_IWGRP) {
            log_err_or_warn (got_force,
                "Logfile is insecure: \"%s\" should not be writable by group "
                "(perms=%04o)", logfile, (st.st_mode & ~S_IFMT));
        }
        if (st.st_mode & S_IWOTH) {
            log_err_or_warn (got_force,
                "Logfile is insecure: \"%s\" should not be writable by other "
                "(perms=%04o)", logfile, (st.st_mode & ~S_IFMT));
        }
    }
    /*  Ensure logfile dir is secure against modification by others.
     */
    rv = path_dirname (logfile, logdir, sizeof (logdir));
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of logfile \"%s\"", logfile);
    }
    rv = path_is_secure (logdir, ebuf, sizeof (ebuf),
        PATH_SECURITY_IGNORE_GROUP_WRITE);
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check logfile dir \"%s\": %s", logdir, ebuf);
    }
    else if (rv == 0) {
        log_err_or_warn (got_force, "Logfile is insecure: %s", ebuf);
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
    struct sigaction sa;
    int              sig;
    int              rv;

    sa.sa_handler = sig_handler;
    sa.sa_flags = 0;
    rv = sigfillset (&sa.sa_mask);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to initialize signal set to full");
    }
    sig = SIGHUP;
    rv = sigaction (sig, &sa, NULL);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to set handler for signal %d (%s)", sig,
                strsignal (sig));
    }
    sig = SIGINT;
    rv = sigaction (sig, &sa, NULL);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to set handler for signal %d (%s)", sig,
                strsignal (sig));
    }
    sig = SIGTERM;
    rv = sigaction (sig, &sa, NULL);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to set handler for signal %d (%s)", sig,
                strsignal (sig));
    }
    xsignal_ignore (SIGPIPE);
    return;
}


static void
sig_handler (int sig)
{
    if (sig == SIGHUP) {
        got_reconfig = sig;
    }
    else if ((sig == SIGINT) || (sig == SIGTERM)) {
        got_terminate = sig;
    }
    return;
}


static void
write_pidfile (const char *pidfile, int got_force)
{
/*  Creates the specified pidfile.
 *  The pidfile must be created after the daemon has finished forking.
 *    It should be written after validation checks that might prevent the
 *    daemon from starting (e.g., after creating the socket and obtaining
 *    the lock), but before the original parent process terminates (i.e.,
 *    before daemonize_fini()).
 */
    char    piddir [PATH_MAX];
    char    ebuf [1024];
    int     rv;
    mode_t  mask;
    FILE   *fp;

    if ((pidfile == NULL) || (*pidfile == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "PIDfile name is undefined");
    }
    /*  The pidfile must be specified with an absolute pathname; o/w, the
     *    unlink() call in destroy_conf() will fail because the daemon has
     *    chdir()'d.
     */
    if (pidfile[0] != '/') {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "PIDfile \"%s\" requires an absolute path", pidfile);
    }
    /*  Ensure pidfile dir is secure against modification by others.
     */
    if (path_dirname (pidfile, piddir, sizeof (piddir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of PIDfile \"%s\"", pidfile);
    }
    rv = path_is_secure (piddir, ebuf, sizeof (ebuf), PATH_SECURITY_NO_FLAGS);
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check PIDfile dir \"%s\": %s", piddir, ebuf);
    }
    else if (rv == 0) {
        log_err_or_warn (got_force, "PIDfile is insecure: %s", ebuf);
    }
    /*  Protect pidfile against unauthorized access by removing write-access
     *    from group and other.
     *  An error removing an old pidfile is not considered fatal.
     */
    mask = umask (0);
    umask (mask | 022);
    do {
        rv = unlink (pidfile);
    } while ((rv < 0) && (errno == EINTR));

    if ((rv < 0) && (errno != ENOENT)) {
        log_msg (LOG_WARNING, "Failed to remove PIDfile \"%s\": %s",
                pidfile, strerror (errno));
    }
    fp = fopen (pidfile, "w");
    umask (mask);
    /*
     *  An error in creating the pidfile is not considered fatal.
     */
    if (!fp) {
        log_msg (LOG_WARNING, "Failed to open PIDfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else if (fprintf (fp, "%d\n", (int) getpid ()) == EOF) {
        log_msg (LOG_WARNING, "Failed to write to PIDfile \"%s\": %s",
            pidfile, strerror (errno));
        (void) fclose (fp);
    }
    else if (fclose (fp) == EOF) {
        log_msg (LOG_WARNING, "Failed to close PIDfile \"%s\": %s",
            pidfile, strerror (errno));
    }
    else {
        return;                         /* success */
    }
    do {
        rv = unlink (pidfile);
    } while ((rv < 0) && (errno == EINTR));

    if ((rv < 0) && (errno != ENOENT)) {
        log_msg (LOG_WARNING, "Failed to remove PIDfile \"%s\": %s",
                pidfile, strerror (errno));
    }
    return;                             /* failure */
}


static void
lock_memory (void)
{
/*  Lock all current and future pages in the virtual memory address space.
 *    Access to locked pages will never be delayed by a page fault.
 *  EAGAIN is tested for up to max_tries in case this is a transient error.
 *    Should there be a nanosleep() between attempts?
 */
#if ! HAVE_MLOCKALL
    errno = ENOSYS;
    log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock pages in memory");
#else
    int       rv;
    int       i = 0;
    const int max_tries = 10;

    while (1) {
        i++;
        rv = mlockall (MCL_CURRENT | MCL_FUTURE);
        if (rv == 0) {
            break;
        }
        if ((errno == EAGAIN) && (i < max_tries)) {
            continue;
        }
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock pages in memory");
    }
    log_msg (LOG_INFO, "Locked all pages in memory");
#endif /* ! HAVE_MLOCKALL */
    return;
}


static void
sock_create (conf_t conf)
{
    char                sockdir [PATH_MAX];
    char                ebuf [1024];
    int                 sd;
    struct sockaddr_un  addr;
    mode_t              mask;
    int                 rv;
    size_t              n;

    assert (conf != NULL);

    if ((conf->socket_name == NULL) || (*conf->socket_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "MUNGE socket name is undefined");
    }
    /*  Ensure socket dir is secure against modification by others.
     */
    rv = path_dirname (conf->socket_name, sockdir, sizeof (sockdir));
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of socket \"%s\"", conf->socket_name);
    }
    rv = path_is_secure (sockdir, ebuf, sizeof (ebuf), PATH_SECURITY_NO_FLAGS);
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check socket dir \"%s\": %s", sockdir, ebuf);
    }
    else if (rv == 0) {
        log_err_or_warn (conf->got_force, "Socket is insecure: %s", ebuf);
    }
    /*  Ensure socket dir is accessible by all.
     */
    rv = path_is_accessible (sockdir, ebuf, sizeof (ebuf));
    if (rv < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check socket dir \"%s\": %s", sockdir, ebuf);
    }
    else if (rv == 0) {
        log_err_or_warn (conf->got_force, "Socket is inaccessible: %s", ebuf);
    }
    /*  Create lockfile for exclusive access to the socket.
     */
    lock_create (conf);
    /*
     *  Remove existing socket from previous instance.
     */
    do {
        rv = unlink (conf->socket_name);
    } while ((rv < 0) && (errno == EINTR));

    if ((rv < 0) && (errno != ENOENT)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to remove socket \"%s\"",
            conf->socket_name);
    }
    else if (rv == 0) {
        log_msg (LOG_INFO, "Removed existing socket \"%s\"",
            conf->socket_name);
    }
    /*  Create socket for communicating with clients.
     */
    sd = socket (PF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create socket");
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, conf->socket_name, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Exceeded maximum length of %lu bytes for socket pathname",
            sizeof (addr.sun_path));
    }
    /*  Ensure socket is accessible by all.
     */
    mask = umask (0);
    rv = bind (sd, (struct sockaddr *) &addr, sizeof (addr));
    umask (mask);

    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to bind socket \"%s\"", conf->socket_name);
    }
    if (listen (sd, MUNGE_SOCKET_BACKLOG) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to listen on socket \"%s\"", conf->socket_name);
    }
    conf->ld = sd;
    log_msg (LOG_INFO, "Created socket \"%s\"", conf->socket_name);
    return;
}


static void
sock_destroy (conf_t conf)
{
    int rv;

    assert (conf != NULL);
    assert (conf->ld >= 0);
    assert (conf->socket_name != NULL);

    if (conf->socket_name) {
        do {
            rv = unlink (conf->socket_name);
        } while ((rv < 0) && (errno == EINTR));

        if (rv < 0) {
            log_msg (LOG_WARNING, "Failed to remove socket \"%s\": %s",
                conf->socket_name, strerror (errno));
        }
    }
    if (conf->ld >= 0) {
        rv = close (conf->ld);
        if (rv < 0) {
            log_msg (LOG_WARNING, "Failed to close socket \"%s\": %s",
                conf->socket_name, strerror (errno));
        }
        conf->ld = -1;
    }
    if (conf->lockfile_name) {
        do {
            rv = unlink (conf->lockfile_name);
        } while ((rv < 0) && (errno == EINTR));

        if (rv < 0) {
            log_msg (LOG_WARNING, "Failed to remove lockfile \"%s\": %s",
                conf->lockfile_name, strerror (errno));
        }
    }
    if (conf->lockfile_fd >= 0) {
        rv = close (conf->lockfile_fd);
        if (rv < 0) {
            log_msg (LOG_WARNING, "Failed to close lockfile \"%s\": %s",
                conf->lockfile_name, strerror (errno));
        }
        conf->lockfile_fd = -1;
    }
    return;
}
