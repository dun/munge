Name:		munge
Version:	0.5.13
Release:	1%{?dist}

# Disable test suite by default; add "--with check" to enable.
%bcond_with check

# Enable hardened build since munged is a long-running daemon.
%global _hardened_build 1

Summary:	MUNGE authentication service
License:	GPLv3+
URL:		https://dun.github.io/munge/
Source0:	https://github.com/dun/munge/releases/download/%{name}-%{version}/%{name}-%{version}.tar.xz

BuildRequires:	gcc
BuildRequires:	bzip2-devel
BuildRequires:	openssl-devel
BuildRequires:	zlib-devel
BuildRequires:	systemd
BuildRequires:	procps
Requires:	%{name}-libs%{?_isa} = %{version}-%{release}
Requires(pre):	shadow-utils
%{?systemd_requires}

%description
MUNGE (MUNGE Uid 'N' Gid Emporium) is an authentication service for creating
and validating credentials.  It is designed to be highly scalable for use
in an HPC cluster environment.  It allows a process to authenticate the
UID and GID of another local or remote process within a group of hosts
having common users and groups.  These hosts form a security realm that is
defined by a shared cryptographic key.  Clients within this security realm
can create and validate credentials without the use of root privileges,
reserved ports, or platform-specific methods.

%package devel
Summary:	MUNGE authentication service development files
License:	LGPLv3+
BuildRequires:	pkgconfig
Requires:	%{name}-libs%{?_isa} = %{version}-%{release}

%description devel
Development files for building applications that use libmunge.

%package libs
Summary:	MUNGE authentication service shared library
License:	LGPLv3+
Requires:	%{name} = %{version}-%{release}

%description libs
The shared library (libmunge) for running applications that use MUNGE.

%prep
%setup -q

%build
%{!?_runstatedir:%global _runstatedir /run}
%configure --disable-static \
    --with-crypto-lib=openssl \
    --with-logrotateddir=%{_sysconfdir}/logrotate.d \
    --with-pkgconfigdir=%{_libdir}/pkgconfig \
    --with-runstatedir=%{_runstatedir} \
    --with-systemdunitdir=%{_unitdir}
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%make_build

%check
%if %{with check}
%make_build check \
    LD_LIBRARY_PATH=%{buildroot}%{_libdir} \
    MUNGE_ROOT=/tmp/munge-$$ VERBOSE=t verbose=t
%endif

%install
%make_install
touch %{buildroot}%{_sysconfdir}/munge/munge.key
touch %{buildroot}%{_localstatedir}/lib/munge/munged.seed
touch %{buildroot}%{_localstatedir}/log/munge/munged.log
touch %{buildroot}%{_runstatedir}/munge/munged.pid

%pre
getent group munge >/dev/null || \
    groupadd -r munge
getent passwd munge >/dev/null || \
    useradd -c "MUNGE authentication service" -d "%{_sysconfdir}/munge" \
    -g munge -s /sbin/nologin -r munge
exit 0

%post
if test ! -f %{_sysconfdir}/munge/munge.key; then
    echo "Run %{_sbindir}/mungekey as the munge user to create a key."
    echo "For example: \"sudo -u munge %{_sbindir}/mungekey -v\"."
    echo "Refer to the mungekey(8) manpage for more information."
fi
%systemd_post munge.service

%post libs -p /sbin/ldconfig

%preun
%systemd_preun munge.service

%postun
%systemd_postun_with_restart munge.service

%postun libs -p /sbin/ldconfig

%files
%{!?_licensedir:%global license %doc}
%license COPYING*
%doc AUTHORS
%doc DISCLAIMER*
%doc HISTORY
%doc JARGON
%doc KEYS
%doc NEWS
%doc PLATFORMS
%doc QUICKSTART
%doc README
%doc THANKS
%doc doc/*
%dir %attr(0700,munge,munge) %{_sysconfdir}/munge
%attr(0600,munge,munge) %config(noreplace) %ghost %{_sysconfdir}/munge/munge.key
%config(noreplace) %{_sysconfdir}/logrotate.d/munge
%config(noreplace) %{_sysconfdir}/sysconfig/munge
%dir %attr(0700,munge,munge) %{_localstatedir}/lib/munge
%attr(0600,munge,munge) %ghost %{_localstatedir}/lib/munge/munged.seed
%dir %attr(0700,munge,munge) %{_localstatedir}/log/munge
%attr(0640,munge,munge) %ghost %{_localstatedir}/log/munge/munged.log
%dir %attr(0755,munge,munge) %ghost %{_runstatedir}/munge
%attr(0644,munge,munge) %ghost %{_runstatedir}/munge/munged.pid
%{_bindir}/*
%{_sbindir}/*
%{_mandir}/man[^3]/*
%{_unitdir}/munge.service

%files devel
%{_includedir}/*
%{_libdir}/libmunge.la
%{_libdir}/libmunge.so
%{_libdir}/pkgconfig/munge.pc
%{_mandir}/man3/*

%files libs
%{_libdir}/libmunge.so.2
%{_libdir}/libmunge.so.2.0.0
