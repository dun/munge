Name:		munge
Version:	0.5.13
Release:	1%{?dist}

Summary:	MUNGE authentication service
Group:		System Environment/Daemons
License:	GPLv3+ and LGPLv3+
URL:		https://dun.github.io/munge/
Source0:	https://github.com/dun/munge/releases/download/%{name}-%{version}/%{name}-%{version}.tar.xz

BuildRequires:	bzip2-devel
BuildRequires:	openssl-devel
BuildRequires:	zlib-devel
BuildRequires:	systemd
Requires:	%{name}-libs = %{version}-%{release}
Requires(pre):	shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%package devel
Summary:	Headers and libraries for developing applications using MUNGE
Group:		Development/Libraries
Requires:	%{name}-libs%{?_isa} = %{version}-%{release}
BuildRequires:	pkgconfig

%package libs
Summary:	Libraries for applications using MUNGE
Group:		System Environment/Libraries
Requires:	%{name} = %{version}-%{release}

%description
MUNGE (MUNGE Uid 'N' Gid Emporium) is an authentication service for creating
and validating credentials.  It is designed to be highly scalable for use
in an HPC cluster environment.  It allows a process to authenticate the
UID and GID of another local or remote process within a group of hosts
having common users and groups.  These hosts form a security realm that is
defined by a shared cryptographic key.  Clients within this security realm
can create and validate credentials without the use of root privileges,
reserved ports, or platform-specific methods.

%description devel
A header file and static library for developing applications using MUNGE.

%description libs
A shared library for applications using MUNGE.

%prep
%setup -q
%{!?_runstatedir:%global _runstatedir /run}

%build
##
# Add the following to the rpm command line to specify 32-bit/64-bit builds:
#   --with arch32  (build 32-bit executables & library)
#   --with arch64  (build 64-bit executables & library)
##
%configure --disable-static \
    %{?_with_arch32: --enable-arch=32} \
    %{?_with_arch64: --enable-arch=64} \
    --program-prefix=%{?_program_prefix:%{_program_prefix}} \
    runstatedir=%{_runstatedir}
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
touch %{buildroot}/%{_sysconfdir}/munge/munge.key
touch %{buildroot}/%{_localstatedir}/lib/munge/munged.seed
touch %{buildroot}/%{_localstatedir}/log/munge/munged.log
touch %{buildroot}/%{_runstatedir}/munge/munged.pid
rm -f %{buildroot}/%{_sysconfdir}/sysconfig/munge
rm -f %{buildroot}/%{_initddir}/munge

%clean
rm -rf %{buildroot}

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
%dir %attr(0711,munge,munge) %{_localstatedir}/lib/munge
%attr(0600,munge,munge) %ghost %{_localstatedir}/lib/munge/munged.seed
%dir %attr(0700,munge,munge) %{_localstatedir}/log/munge
%attr(0640,munge,munge) %ghost %{_localstatedir}/log/munge/munged.log
%dir %attr(0755,munge,munge) %{_runstatedir}/munge
%attr(0644,munge,munge) %ghost %{_runstatedir}/munge/munged.pid
%{_bindir}/*
%{_sbindir}/*
%{_mandir}/*[^3]/*
%{_tmpfilesdir}/munge.conf
%{_unitdir}/munge.service

%files devel
%{_includedir}/*
%{_libdir}/*.la
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_mandir}/*3/*

%files libs
%{_libdir}/*.so.*
