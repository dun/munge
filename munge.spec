# $Id$

Name:		munge
Version:	0.4.1
Release:	1

Summary:	Munge Uid 'N' Gid Emporium
Group:		System Environment/Daemons
License:	GPL
URL:		http://www.llnl.gov/linux/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tar.gz

%package devel
Summary:	Headers and libraries for developing applications using MUNGE
Group:		Development/Libraries

%package libs
Summary:	Libraries for applications using MUNGE
Group:		System Environment/Libraries

%description
MUNGE (Munge Uid 'N' Gid Emporium) is a service for creating and validating
credentials in order to allow a process to securely authenticate the UID and
GID of another local or remote process within a security realm.  Clients can
create and validate these credentials without the use of root privileges,
reserved ports, or platform-specific methods.

%description devel
A header file and static library for developing applications using MUNGE.

%description libs
A shared library for applications using MUNGE.

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
if [ $1 = 1 ]; then
  /sbin/chkconfig --add munge
fi

%post libs
/sbin/ldconfig %{_libdir}

%preun
if [ $1 = 0 ]; then
  /sbin/service munge stop >/dev/null 2>&1 || :
  /sbin/chkconfig --del munge
fi

%postun
if [ $1 -ge 1 ]; then
  /sbin/service munge condrestart >/dev/null 2>&1 || :
fi

%postun libs
/sbin/ldconfig %{_libdir}

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
%{_sbindir}/*
%{_mandir}/*[^3]/*

%files devel
%{_includedir}/*
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so
%{_mandir}/*3/*

%files libs
%{_libdir}/*.so.*
