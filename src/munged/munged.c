/*****************************************************************************
 *  $Id: munged.c,v 1.6 2003/05/30 01:20:12 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
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
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "conf.h"
#include "crypto_thread.h"
#include "munge_defs.h"
#include "posignal.h"
#include "random.h"
#include "sock.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void handle_signals (void);
static void exit_handler (int signum);
static void segv_handler (int signum);
static int  daemonize_init (void);
static void daemonize_fini (int fd);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

conf_t  conf = NULL;                    /* global configuration struct       */
int     done = 0;                       /* global flag set true for exit     */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    int fd = -1;

    log_open_file (stderr, argv[0], LOG_NOTICE, LOG_OPT_PRIORITY);

    handle_signals ();

    conf = create_conf ();
    parse_cmdline (conf, argc, argv);

    if (!conf->got_foreground) {
        fd = daemonize_init ();
    }
    /*  FIXME: Parse config file.  */

    lookup_ip_addr (conf);
    random_init (conf->seed_name);
    crypto_thread_init ();
    create_subkeys (conf);

    if (!conf->got_foreground) {
        /*
         *  FIXME: Revamp logfile kludge.
         */
        FILE *fp = fopen (MUNGED_LOGFILE, "a");
        log_open_file (fp, NULL, LOG_DEBUG,
            LOG_OPT_JUSTIFY | LOG_OPT_PRIORITY | LOG_OPT_TIMESTAMP);
        daemonize_fini (fd);
    }

    log_msg (LOG_NOTICE, "Starting %s daemon %s (pid %d)",
        PACKAGE, VERSION, (int) getpid());

    munge_sock_create (conf);
    munge_sock_accept (conf);
    munge_sock_destroy (conf);

    crypto_thread_fini ();
    random_fini (conf->seed_name);
    destroy_conf (conf);

    log_msg (LOG_NOTICE, "Stopping %s daemon %s (pid %d)",
        PACKAGE, VERSION, (int) getpid());

    exit (EMUNGE_SUCCESS);
}


static void
handle_signals (void)
{
    if (posignal (SIGHUP, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGHUP);
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
exit_handler (int signum)
{
    log_msg (LOG_NOTICE, "Exiting on signal=%d", signum);
    done = 1;
    return;
}


static void
segv_handler (int signum)
{
    log_err (EMUNGE_SNAFU, LOG_CRIT,
        "Exiting on signal=%d (segmentation violation)", signum);
    assert (1);                         /* not reached */
}


static int
daemonize_init (void)
{
/*  Begins the daemonization of the process.
 *  Despite the fact that this routine backgrounds the process, control
 *    will not be returned to the shell until daemonize_fini() is called.
 *  Returns an 'fd' to pass to daemonize_fini() to complete the daemonization.
 */
    struct rlimit limit;
    int           fds[2];
    pid_t         pid;
    char          c;

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
    /*  Automatically background the process and
     *    ensure child is not a process group leader.
     */
    if ((pid = fork ()) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to create child process");
    }
    else if (pid > 0) {
        if (close (fds[1]) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close write-pipe in parent");
        }
        if (read (fds[0], &c, 1) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Read failed while awaiting EOF from grandchild");
        }
        exit (0);
    }
    if (close (fds[0]) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close read-pipe in child");
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
     *  XXX: Avoid relative pathnames from this point on!
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
    /*  Signal grandparent process to terminate.
     */
    if ((fd >= 0) && (close (fd) < 0)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close write-pipe in grandchild");
    }
    return;
}
