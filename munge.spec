# $Id: munge.spec,v 1.27 2004/12/22 01:25:37 dun Exp $

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
MUNGE (Munge Uid 'N' Gid Emporium) is a service for creating and validating
credentials in order to allow a process to securely authenticate the UID and
GID of another local or remote process within a security realm.  Clients can
create and validate these credentials without the use of root privileges,
reserved ports, or platform-specific methods.

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
#
# Remove chkconfig droppings from the "-1 priority" bug.
#
if [ -L /etc/rc.d/rc0.d/K-1munge ]; then
  find /etc/rc.d/rc?.d/ -type l -name "[SK]-1munge" -exec rm -f {} \;
  /sbin/chkconfig --del munge
  /sbin/chkconfig --add munge
fi

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
%config(noreplace) %{_sysconfdir}/init.d/*
%config(noreplace) %{_sysconfdir}/sysconfig/*
%{_bindir}/*
%{_includedir}/*
%{_libdir}/*
%{_mandir}/*/*
%{_sbindir}/*
