# $Id: munge.spec,v 1.3 2002/12/20 21:19:31 dun Exp $

Name:		munge
Version:	0.0
Release:	1

Summary:	Munge
Group:		System Environment/Libraries
License:	GPL
URL:		http://www.llnl.gov/linux/munge/

BuildRoot:	%{_tmppath}/%{name}-%{version}

Source0:	%{name}-%{version}.tgz

%description
Munge is a library allowing Unix credentials to be securely forwarded to
remote processes within an administrative domain.

%prep
%setup

%build
%configure
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
%doc NEWS
%doc README
#%config(noreplace) /etc/munge.conf
#%config(noreplace) /etc/logrotate.d/munge
#%config(noreplace) /etc/rc.d/init.d/munge
%{_includedir}/*
%{_libdir}/*
#%{_mandir}/*/*
#%{_sbindir}/*
