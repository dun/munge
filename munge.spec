# $Id: munge.spec,v 1.22 2004/10/29 18:36:51 dun Exp $

Name:		munge
Version:	0
Release:	1

Summary:	Munge Uid 'N' Gid Emporium
Group:		System Environment/Libraries
License:	GPL
URL:		http://www.llnl.gov/linux/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tar.gz

%description
MUNGE (Munge Uid 'N' Gid Emporium) is a service for creating and
validating credentials in order to allow a process to securely
authenticate the UID and GID of another local or remote process
within an administrative domain.  Clients can create and validate
these credentials without the use of root privileges, reserved ports,
or platform-specific methods.

A credential is created and validated by the local munged daemon
running on each node within the administrative domain.  A client
creates or validates a given credential through the use of the
libmunge library or munge/unmunge executables; these are responsible
for communicating with the local daemon on behalf of the client.

The contents of the credential (including any application-supplied
data) are encrypted with a key shared by all munged daemons within the
administrative domain.  The integrity of the credential is ensured by
a message authentication code (MAC).  The credential is valid for a
limited time defined by its time-to-live (TTL).  The daemon ensures
unexpired credentials are not being replayed on that particular host.
The application-supplied data can be used for purposes such as
embedding the destination's address to ensure the credential is valid
on only that host.  The internal format of the credential is encoded
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

%post
/sbin/ldconfig %{_libdir}
if [ $1 = 1 ]; then
  /sbin/chkconfig --add munge
fi

%preun
if [ $1 = 0 ]; then
  /sbin/service munge stop >/dev/null 2>&1 || :
  /sbin/chkconfig --del munge
fi

%postun
/sbin/ldconfig %{_libdir}
if [ $1 -ge 1 ]; then
  /sbin/service munge condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,0755)
%doc AUTHORS
%doc BUGS
%doc COPYING
%doc ChangeLog
%doc DISCLAIMER
%doc HISTORY
%doc INSTALL
%doc JARGON
%doc NEWS
%doc PLATFORMS
%doc README
%doc TODO
%doc doc/*
#%config(noreplace) /etc/munge/munge.conf
#%config(noreplace) /etc/logrotate.d/munge
%config(noreplace) %{_sysconfdir}/init.d/*
%{_bindir}/*
%{_includedir}/*
%{_libdir}/*
#%{_mandir}/*/*
%{_sbindir}/*
