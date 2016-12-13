[![Build Status](https://travis-ci.org/dun/munge.svg?branch=master)](https://travis-ci.org/dun/munge)
[![Coverity Scan](https://scan.coverity.com/projects/dun-munge/badge.svg)](https://scan.coverity.com/projects/dun-munge)

### MUNGE Uid 'N' Gid Emporium

MUNGE (_MUNGE Uid 'N' Gid Emporium_) is an authentication service for
creating and validating credentials.  It is designed to be highly scalable
for use in an HPC cluster environment.  It allows a process to authenticate
the UID and GID of another local or remote process within a group of hosts
having common users and groups.  These hosts form a security realm that is
defined by a shared cryptographic key.  Clients within this security realm
can create and validate credentials without the use of root privileges,
reserved ports, or platform-specific methods.

- [Overview](../../wiki/Man-7-munge)
- [Installation Guide](../../wiki/Installation-Guide)
- [License Information](../../wiki/License-Info)
- [Man Pages](../../wiki/Man-Pages)
- [Atom feed for Releases](../../releases.atom)
- [Verifying Releases](../../wiki/Verifying-Releases)
- [Latest Release](../../releases/latest)
