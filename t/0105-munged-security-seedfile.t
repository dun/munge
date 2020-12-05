#!/bin/sh

test_description='Check munged security of seedfile'

. "$(dirname "$0")/sharness.sh"

# Set up the environment for checking the seedfile.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

##
# FIXME
# random.c:_random_read_entropy_from_file,_random_read_seed
# Is an absolute path required?
##
# seedfile regular file
# seedfile missing
# seedfile ignored when symlink
# seedfile ignored when open fails
# seedfile ignored when not a file
# seedfile ignored when not owned by euid
# seedfile readable by trusted group
# seedfile ignored when readable by untrusted group
# seedfile writable by trusted group
# seedfile ignored when writable by untrusted group
# seedfile ignored when readable by group
# seedfile ignored when writable by group
# seedfile ignored when readable by other
# seedfile ignored when writable by other
# seedfile dir owned by root
# seedfile dir owned by euid
# seedfile dir owned by other failure
# seedfile dir owned by other override
# seedfile dir writable by trusted group
# seedfile dir writable by untrusted group failure
# seedfile dir writable by group failure
# seedfile dir writable by group override
# seedfile dir writable by group with sticky bit
# seedfile dir writable by other failure
# seedfile dir writable by other override
# seedfile dir writable by other with sticky bit
# seedfile 0600 perms (without trusted group) (test w/ 0 umask)
# seedfile 0660 perms with trusted group (test w/ 0 umask)
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
