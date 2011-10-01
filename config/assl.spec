%define name		assl
%define version		0.10.2
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
Requires: clens-devel >= 0.0.5, openssl-devel >= 1.0.0d

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
* Wed Aug 31 2011 - dhill 0.10.2-1
- Rework SSL negotiation to take up to roughly 10 seconds
- Attempt a connection to each address returned by host lookup instead of just the first address returned
* Tue Jul 26 2011 - davec 0.10.1-1
- Improve portability
- Don't link against clens directly from library
- Minor cleanup
* Tue Jul 03 2011 - davec 0.10.0-1
- Create
