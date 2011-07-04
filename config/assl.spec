# $assl$

%define name		assl
%define version		0.10.0
%define release		1

Name: 		%{name}
Summary: 	Library that provides a sane interface to the OpenSSL API
Version: 	%{version}
Release: 	%{release}
License: 	ISC
Group: 		System Environment/Libraries
URL:		http://opensource.conformal.com/wiki/assl
Source: 	%{name}-%{version}.tar.gz
Buildroot:	%{_tmppath}/%{name}-%{version}-buildroot
Prefix: 	/usr
Requires:	openssl >= 1.0.0d

%description
assl (Agglomerated SSL) was written in order to hide the awful OpenSSL API. It
strives to reuse the OpenSSL APIs and provide a much simpler and sane
interface for programmers that are interested in writing applications that
require the SSL/TLS protocol for secure communications.

%prep
%setup -q

%build
make

%install
make install DESTDIR=$RPM_BUILD_ROOT LOCALBASE=/usr

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
/usr/lib/libassl.so.*


%package devel
Summary: Libraries and header files to develop applications using assl
Group: Development/Libraries
Requires: clens >= 0.0.5, openssl-devel >= 1.0.0d

%description devel
This package contains the libraries, include files, and documentation to
develop applications with assl.

%files devel
%defattr(-,root,root)
%doc /usr/share/man/man?/*
/usr/include/assl.h
/usr/lib/libassl.so
/usr/lib/libassl.a

%changelog
* Tue Jul 03 2011 - davec 0.10.0-1
- Create
