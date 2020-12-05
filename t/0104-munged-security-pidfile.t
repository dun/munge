#!/bin/sh

test_description='Check munged security of pidfile'

. "$(dirname "$0")/sharness.sh"

# Set up the environment for checking the pidfile.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

##
# FIXME
# munged.c:write_pidfile
# Is an absolute path required?
##
# pidfile with absolute path
# pidfile with relative path failure
# pidfile dir owned by root
# pidfile dir owned by euid
# pidfile dir owned by other failure
# pidfile dir owned by other override
# pidfile dir writable by trusted group
# pidfile dir writable by untrusted group failure
# pidfile dir writable by group failure
# pidfile dir writable by group override
# pidfile dir writable by group with sticky bit
# pidfile dir writable by other failure
# pidfile dir writable by other override
# pidfile dir writable by other with sticky bit
# pidfile removal of previous file
# pidfile contains munged pid (grep pid from logfile)
# pidfile failure to open
# pidfile failure to write
# pidfile 0644 perms (without trusted group) (test w/ 0 umask)
# pidfile 0664 perms with trusted group (test w/ 0 umask)
##

test_expect_failure 'finish writing tests' '
    false
'

# Clean up after a munged process that may not have terminated.
##
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
