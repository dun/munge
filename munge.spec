Name:		munge
Version:	0.5.10
Release:	1%{?dist}

Summary:	MUNGE Uid 'N' Gid Emporium
Group:		System Environment/Daemons
License:	GPLv3+ and LGPLv3+
URL:		https://munge.googlecode.com/
Requires:	%{name}-libs = %{version}-%{release}

%if 0%{?suse_version} >= 1100
BuildRequires:	libbz2-devel
BuildRequires:	libopenssl-devel
BuildRequires:	zlib-devel
%else
%if 0%{?sles_version} || 0%{?suse_version}
BuildRequires:	bzip2
BuildRequires:	openssl-devel
BuildRequires:	zlib-devel
%else
BuildRequires:	bzip2-devel
BuildRequires:	openssl-devel
BuildRequires:	zlib-devel
%endif
%endif
BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tar.bz2

Requires(pre):  shadow-utils

%package devel
Summary:	Headers and libraries for developing applications using MUNGE
Group:		Development/Libraries
Requires:	%{name}-libs = %{version}-%{release}

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
%setup

%build
%ifos aix5.3 aix5.2 aix5.1 aix5.0 aix4.3
##
# Add the following to the rpm command line to specify 32-bit/64-bit builds:
#   --define 'bitarch all'      (build 32-bit executables & multiarch library)
#   --define 'bitarch 32'       (build 32-bit executables & library)
#   --define 'bitarch 64'       (build 64-bit executables & library)
#
# Add the following to the rpm command line to specify shared/static libraries:
#   --define 'linkage all'      (build both shared & static libraries)
#   --define 'linkage shared'   (build shared libraries only)
#   --define 'linkage static'   (build static libraries only)
##
%{?bitarch:BITARCH="%{bitarch}"}
case "$BITARCH" in
  32) BITARCH="32" ;;
  64) BITARCH="64" ;;
  32_64|all|any|both|"") BITARCH="64 32" ;;
  *) echo "bitarch must be one of [ all | 32 | 64 ]" 1>&2; exit 1 ;;
esac
%{?linkage:LINKAGE="%{linkage}"}
case "$LINKAGE" in
  shared|dynamic) LINKAGE="shared" ;;
  static) LINKAGE="static" ;;
  all|any|both|"") LINKAGE="static shared" ;;
  *) echo "linkage must be one of [ all | shared | static ]" 1>&2; exit 1 ;;
esac
TOP="`pwd`"
TMP="$TOP/tmp-$$"
OBJECT_MODE="32"
export OBJECT_MODE
for linkage in $LINKAGE; do
  [ "$linkage" = "static" ] && nonlinkage="shared" || nonlinkage="static"
  for bitarch in $BITARCH; do
    %configure -C --enable-arch="$bitarch" \
      --enable-"$linkage" --disable-"$nonlinkage" \
      --program-prefix=%{?_program_prefix:%{_program_prefix}}
    rm -rf "$TMP/$linkage-$bitarch"
    mkdir -p "$TMP/$linkage-$bitarch"
    ( cd src/libmunge && make install DESTDIR="$TMP/$linkage-$bitarch" )
    make clean
    rm -rf "$TMP/$linkage-$bitarch-lib"
    mkdir -p "$TMP/$linkage-$bitarch-lib"
    ( cd "$TMP/$linkage-$bitarch-lib" && \
      ar -X"$bitarch" x "$TMP/$linkage-$bitarch%{_libdir}/libmunge.a" )
  done
done
rm -f "libmunge.a"
( cd "$TMP" && ar -Xany cr "$TOP/libmunge.a" *-lib/* )
rm -rf "$TMP"
make
%else
##
# Add the following to the rpm command line to specify 32-bit/64-bit builds:
#   --with arch32               (build 32-bit executables & library)
#   --with arch64               (build 64-bit executables & library)
##
%configure \
  %{?_with_arch32: --enable-arch=32} \
  %{?_with_arch64: --enable-arch=64} \
  --program-prefix=%{?_program_prefix:%{_program_prefix}}
make
%endif

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"
DESTDIR="$RPM_BUILD_ROOT" make install
touch "$RPM_BUILD_ROOT"/%{_sysconfdir}/munge/munge.key
touch "$RPM_BUILD_ROOT"/%{_localstatedir}/lib/munge/munge.seed
touch "$RPM_BUILD_ROOT"/%{_localstatedir}/log/munge/munged.log
touch "$RPM_BUILD_ROOT"/%{_localstatedir}/run/munge/munged.pid
%ifos aix5.3 aix5.2 aix5.1 aix5.0 aix4.3
[ -f "libmunge.a" ] && cp "libmunge.a" "$RPM_BUILD_ROOT"%{_libdir}
%endif

%clean
rm -rf "$RPM_BUILD_ROOT"

%pre
/usr/bin/getent group munge >/dev/null 2>&1 || \
  /usr/sbin/groupadd -r munge
/usr/bin/getent passwd munge >/dev/null 2>&1 || \
  /usr/sbin/useradd -c "MUNGE Uid 'N' Gid Emporium" \
  -d "%{_sysconfdir}/munge" -g munge -s /bin/false -r munge

%post
if [ ! -e %{_sysconfdir}/munge/munge.key -a -c /dev/urandom ]; then
  /bin/dd if=/dev/urandom bs=1 count=1024 \
    >%{_sysconfdir}/munge/munge.key 2>/dev/null
  /bin/chown munge:munge %{_sysconfdir}/munge/munge.key
  /bin/chmod 0400 %{_sysconfdir}/munge/munge.key
fi
##
# Fix files for munge user when upgrading to 0.5.11.
if ! /bin/egrep '^[ 	]*USER=' %{_sysconfdir}/sysconfig/munge \
    >/dev/null 2>&1; then
  /bin/chown munge:munge %{_sysconfdir}/munge/* %{_localstatedir}/*/munge/* \
    %{_localstatedir}/run/munge >/dev/null 2>&1
fi
##
# Fix subsys lockfile name when upgrading to 0.5.11.
if [ -f /var/lock/subsys/munged ]; then
  /bin/mv /var/lock/subsys/munged /var/lock/subsys/munge
fi
##
if [ -x /sbin/chkconfig ]; then /sbin/chkconfig --add munge; fi

%post libs
if [ -x /sbin/ldconfig ]; then /sbin/ldconfig %{_libdir}; fi

%preun
if [ $1 -eq 0 ]; then
  %{_sysconfdir}/init.d/munge stop >/dev/null 2>&1 || :
  if [ -x /sbin/chkconfig ]; then /sbin/chkconfig --del munge; fi
fi

%postun
if [ $1 -ge 1 ]; then
  %{_sysconfdir}/init.d/munge try-restart >/dev/null 2>&1 || :
fi

%postun libs
if [ -x /sbin/ldconfig ]; then /sbin/ldconfig %{_libdir}; fi

%files
%defattr(-,root,root,0755)
%doc AUTHORS
%doc COPYING
%doc DISCLAIMER*
%doc HISTORY
%doc INSTALL
%doc JARGON
%doc NEWS
%doc PLATFORMS
%doc QUICKSTART
%doc README*
%doc doc/*
%dir %attr(0700,munge,munge) %{_sysconfdir}/munge
%attr(0600,munge,munge) %config(noreplace) %ghost %{_sysconfdir}/munge/munge.key
%config(noreplace) %{_sysconfdir}/sysconfig/munge
%{?_initddir:%{_initddir}}%{!?_initddir:%{_initrddir}}/munge
%dir %attr(0711,munge,munge) %{_localstatedir}/lib/munge
%attr(0600,munge,munge) %ghost %{_localstatedir}/lib/munge/munge.seed
%dir %attr(0700,munge,munge) %{_localstatedir}/log/munge
%attr(0640,munge,munge) %ghost %{_localstatedir}/log/munge/munged.log
%dir %attr(0755,munge,munge) %ghost %{_localstatedir}/run/munge
%attr(0644,munge,munge) %ghost %{_localstatedir}/run/munge/munged.pid
%{_bindir}/*
%{_sbindir}/*
%{_mandir}/*[^3]/*

%files devel
%defattr(-,root,root,0755)
%{_includedir}/*
%{_libdir}/*.la
%{_mandir}/*3/*
%ifnos aix5.3 aix5.2 aix5.1 aix5.0 aix4.3
%{_libdir}/*.a
%{_libdir}/*.so
%endif

%files libs
%defattr(-,root,root,0755)
%ifnos aix5.3 aix5.2 aix5.1 aix5.0 aix4.3
%{_libdir}/*.so.*
%else
%{_libdir}/*.a
%endif
