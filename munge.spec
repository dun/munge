# $Id: munge.spec,v 1.8 2003/04/30 17:58:59 dun Exp $

Name:		munge
Version:	0.0
Release:	1

Summary:	Munge Uid 'N' Gid Emporium
Group:		System Environment/Libraries
License:	GPL
URL:		http://www.llnl.gov/linux/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tgz

%description
Munge is a mechanism for creating/verifying credentials in order to allow
a process to securely authenticate the UID/GID of another local or remote
process within an administrative domain.  Processes can create and verify
these credentials without the use of root privileges or reserved ports.

In actuality, a credential is created and verified by the local root
'munged' daemon running on each node.  But a process creates or verifies
a given credential through the use of a munge client such as the libmunge
library or munge/unmunge executables; these clients are responsible for
communicating with the local munged daemon.

The contents of the credential (including any application-supplied data)
are encrypted.  The integrity of the credential is ensured by a MAC.
The credential is valid for a limited time defined by its TTL.  The daemon
ensures unexpired credentials are not being replayed on a particular host.
The application-supplied data can be used for purposes such as embedding the
destination's address to ensure the credential is valid on only that host.
The credential itself is base64 encoded to allow it to be transmitted over
virtually any transport.

%prep
%setup

%build
%configure --program-prefix=%{?_program_prefix:%{_program_prefix}}
make

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"
DESTDIR="$RPM_BUILD_ROOT" make install

%clean
rm -rf "$RPM_BUILD_ROOT"

#%pre
#if [ -x /etc/rc.d/init.d/munge ]; then
#  if /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
#    /etc/rc.d/init.d/munge stop
#  fi
#fi
#
#%post
#if [ -x /etc/rc.d/init.d/munge ]; then
#  [ -x /sbin/chkconfig ] && /sbin/chkconfig --del munge
#  [ -x /sbin/chkconfig ] && /sbin/chkconfig --add munge
#  if ! /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
#    /etc/rc.d/init.d/munge start
#  fi
#fi
#
#%preun
#if [ "$1" = 0 ]; then
#  if [ -x /etc/rc.d/init.d/munge ]; then
#    [ -x /sbin/chkconfig ] && /sbin/chkconfig --del munge
#    if /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
#      /etc/rc.d/init.d/munge stop
#    fi
#  fi
#fi
#
%post
if [ "$1" = 1 ]; then
  /sbin/ldconfig %{_libdir}
fi

%postun
if [ "$1" = 0 ]; then
  /sbin/ldconfig %{_libdir}
fi

%files
%defattr(-,root,root,0755)
%doc AUTHORS
%doc COPYING
%doc ChangeLog
%doc DISCLAIMER
%doc INSTALL
%doc JARGON
%doc NEWS
%doc README
%doc TODO
#%config(noreplace) /etc/munge.conf
#%config(noreplace) /etc/logrotate.d/munge
#/etc/rc.d/init.d/munge
%{_bindir}/*
%{_includedir}/*
%{_libdir}/*
#%{_mandir}/*/*
#%{_sbindir}/*
