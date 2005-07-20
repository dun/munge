/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2005 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
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
#include "crypto_thread.h"
#include "gids.h"
#include "job.h"
#include "log.h"
#include "missing.h"
#include "munge_defs.h"
#include "posignal.h"
#include "random.h"
#include "replay.h"
#include "timer.h"
#include "version.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void handle_signals (void);
static void exit_handler (int signum);
static void segv_handler (int signum);
static int  daemonize_init (void);
static void daemonize_fini (int fd);
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

    handle_signals ();

    auth_recv_init ();
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);

    if (!conf->got_foreground) {
        fd = daemonize_init ();
    }
    /*  FIXME: Parse config file.  */

    if (!conf->got_foreground) {
        /*
         *  FIXME: Revamp logfile kludge.
         */
        FILE *fp = fopen (MUNGED_LOGFILE, "a");
        log_open_file (fp, NULL, priority,
            LOG_OPT_JUSTIFY | LOG_OPT_PRIORITY | LOG_OPT_TIMESTAMP);
        daemonize_fini (fd);
    }

    lookup_ip_addr (conf);
    random_init (conf->seed_name);
    crypto_thread_init ();
    create_subkeys (conf);
    conf->gids = gids_create ();
    replay_init ();
    timer_init ();

    log_msg (LOG_NOTICE, "Starting %s daemon (pid %d)",
        META_ALIAS, (int) getpid ());

    sock_create (conf);
    job_accept (conf);
    sock_destroy (conf);

    timer_fini ();
    replay_fini ();
    gids_destroy (conf->gids);
    crypto_thread_fini ();
    random_fini (conf->seed_name);
    destroy_conf (conf);

    log_msg (LOG_NOTICE, "Stopping %s daemon (pid %d)",
        META_ALIAS, (int) getpid ());

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


static void
sock_create (conf_t conf)
{
    struct sockaddr_un  addr;
    int                 sd;
    int                 n;
    mode_t              mask;

    assert (conf != NULL);

    if ((conf->socket_name == NULL) || (*conf->socket_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Munge socket has no name");
    }
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to create socket");
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, conf->socket_name, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Exceeded maximum length of socket pathname");
    }
    mask = umask (0);                   /* ensure sock access perms of 0777 */

    if (conf->got_force) {
        unlink (conf->socket_name);     /* ignoring errors */
    }
    if (bind (sd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to bind to \"%s\"", conf->socket_name);
    }

    umask (mask);                       /* restore umask */

    if (listen (sd, MUNGE_SOCKET_BACKLOG) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to listen to \"%s\"", conf->socket_name);
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
