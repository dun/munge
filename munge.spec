# $Id: munge.spec,v 1.12 2003/05/30 23:59:55 dun Exp $

Name:		munge
Version:	0.1
Release:	1

Summary:	Munge Uid 'N' Gid Emporium
Group:		System Environment/Libraries
License:	GPL
URL:		http://www.llnl.gov/linux/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tgz

%description
MUNGE (Munge Uid 'N' Gid Emporium) is a mechanism for creating/validating
credentials in order to allow a process to securely authenticate the
UID/GID of another local or remote process within an administrative domain.
Processes can create and validate these credentials without the use of
root privileges or reserved ports.

In actuality, a credential is created and validated by the local root
'munged' daemon running on each node in the administrative domain.
But a process creates or validates a given credential through the use
of the libmunge library or munge/unmunge executables; these clients are
responsible for communicating with the local daemon.

The contents of the credential (including any application-supplied
data) are encrypted with a key shared by all 'munged' daemons within the
administrative domain.  The integrity of the credential is ensured by a MAC.
The credential is valid for a limited time defined by the daemon's TTL.
The daemon ensures unexpired credentials are not being replayed on that
particular host.  The application-supplied data can be used for purposes
such as embedding the destination's address to ensure the credential is
valid on only that host.  The internal format of the credential is encoded
in a platform-independent manner.  And the credential itself is base64
encoded to allow it to be transmitted over virtually any transport.

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

%pre
if [ -x /etc/rc.d/init.d/munge ]; then
  if /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
    /etc/rc.d/init.d/munge stop
  fi
fi

%post
/sbin/ldconfig %{_libdir}
if [ -x /etc/rc.d/init.d/munge ]; then
  [ -x /sbin/chkconfig ] && /sbin/chkconfig --del munge
  [ -x /sbin/chkconfig ] && /sbin/chkconfig --add munge
  if ! /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
    /etc/rc.d/init.d/munge start
  fi
fi

%preun
if [ "$1" = 0 ]; then
  if [ -x /etc/rc.d/init.d/munge ]; then
    [ -x /sbin/chkconfig ] && /sbin/chkconfig --del munge
    if /etc/rc.d/init.d/munge status | grep running >/dev/null 2>&1; then
      /etc/rc.d/init.d/munge stop
    fi
  fi
fi

%postun
/sbin/ldconfig %{_libdir}

%files
%defattr(-,root,root,0755)
%doc AUTHORS
%doc COPYING
%doc ChangeLog
%doc DISCLAIMER
%doc HISTORY
%doc INSTALL
%doc JARGON
%doc NEWS
%doc README
%doc TODO
%doc doc/*
#%config(noreplace) /etc/munge/munge.conf
#%config(noreplace) /etc/logrotate.d/munge
/etc/rc.d/init.d/munge
%{_bindir}/*
%{_includedir}/*
%{_libdir}/*
#%{_mandir}/*/*
%{_sbindir}/*
