# $Id$

Name:		munge
Version:	0
Release:	0

Summary:	MUNGE Uid 'N' Gid Emporium
Group:		System Environment/Daemons
License:	GPL
URL:		http://home.gna.org/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tar

%package devel
Requires:	%{name} = %{version}-%{release}
Summary:	Headers and libraries for developing applications using MUNGE
Group:		Development/Libraries

%package libs
Requires:	%{name} = %{version}-%{release}
Summary:	Libraries for applications using MUNGE
Group:		System Environment/Libraries

%description
MUNGE (MUNGE Uid 'N' Gid Emporium) is an authentication service for
creating and validating credentials in order to allow a process to securely
authenticate the UID and GID of another local or remote process within a
security realm.  Clients can create and validate these credentials without
the use of root privileges, reserved ports, cryptographic libraries, or
platform-specific methods.

%description devel
A header file and static library for developing applications using MUNGE.

%description libs
A shared library for applications using MUNGE.

%prep
%setup -n munge

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
%ifos aix5.3 aix5.2 aix5.1 aix5.0 aix4.3
[ -f "libmunge.a" ] && cp "libmunge.a" "$RPM_BUILD_ROOT"%{_libdir}
%endif

%clean
rm -rf "$RPM_BUILD_ROOT"

%post
if [ ! -e %{_sysconfdir}/munge/munge.key -a -c /dev/urandom ]; then
  /bin/dd if=/dev/urandom bs=1 count=1024 \
    >%{_sysconfdir}/munge/munge.key 2>/dev/null
  /bin/chown daemon:daemon %{_sysconfdir}/munge/munge.key
  /bin/chmod 0400 %{_sysconfdir}/munge/munge.key
fi
if [ -x /sbin/chkconfig ]; then /sbin/chkconfig --add munge; fi

%post libs
if [ -x /sbin/ldconfig ]; then /sbin/ldconfig %{_libdir}; fi

%preun
if [ "$1" = 0 ]; then
  %{_sysconfdir}/init.d/munge stop >/dev/null 2>&1 || :
  if [ -x /sbin/chkconfig ]; then /sbin/chkconfig --del munge; fi
fi

%postun
if [ "$1" -ge 1 ]; then
  %{_sysconfdir}/init.d/munge condrestart >/dev/null 2>&1 || :
fi

%postun libs
if [ -x /sbin/ldconfig ]; then /sbin/ldconfig %{_libdir}; fi

%files
%defattr(-,root,root,0755)
%doc AUTHORS
%doc BUGS
%doc ChangeLog
%doc COPYING
%doc DISCLAIMER
%doc HISTORY
%doc INSTALL
%doc JARGON
%doc NEWS
%doc PLATFORMS
%doc QUICKSTART
%doc README*
%doc TODO
%doc doc/*
%dir %attr(0700,daemon,daemon) %config %{_sysconfdir}/munge
%config(noreplace) %{_sysconfdir}/*/*
%dir %attr(0711,daemon,daemon) %config %{_localstatedir}/lib/munge
%dir %attr(0700,daemon,daemon) %config %{_localstatedir}/log/munge
%dir %attr(0755,daemon,daemon) %config %{_localstatedir}/run/munge
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
