%define name		assl
%define version		1.5.0
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
/usr/include/assl_socket.h
/usr/lib/libassl.so
/usr/lib/libassl.a

%changelog
* Thu Nov 07 2013 - dhill 1.5.0-1
- Add _opts versions of assl_connect and assl_serve
  which allow setting the socket buffer sizes
* Fri Jun 28 2013 - dhill 1.4.1-1
- Plug memory leak in assl_destroy_mem_certs
* Fri May 31 2013 - davec 1.4.0-1
- Add wrapper function (assl_get_ssl_error) to allow retrieval of OpenSSL
  errors in a platform agnostic manner
- Fix OpenBSD port Makefile for modern OpenBSD ports
* Wed Apr 17 2013 - davec 1.3.0-1
- Stop shipping pic.a libs that are no longer needed on OpenBSD
- Improve thread safety
- Other minor code cleanup
* Fri Jan 04 2013 - davec 1.2.0-1
- Add support for OpenSSL 1.0.1c
- Add support for TLS 1.1 and TLS 1.2
- Fall back to TLS 1.0 on older OpenSSL versions
- Use DH parameters from certs
- Always initialize the named curve in order to enable ECDHE
- Remove the 'version: ' prefix from assl_verstring
- Add support for Bitrig
- Other minor code cleanup
* Tue Jul 17 2012 - davec 1.1.0-1
- Support clang builds
- Add function used to obtain file descriptor from context
- Remove support for SSL version 2
- Remove all assl_event APIs
- Update man page with new and removed functions
- Limit to a single initialization
- Other minor code cleanup
* Tue Apr 24 2012 - drahn 1.0.0-1
- change to using libevent2
- Other minor cleanup and bug fixes
* Mon Feb 27 2012 - davec 0.12.2-1
- Add support for latest version of libevent
- Improve error reporting when loading file certificates
- Add build versioning on Linux to match support on BSD
- Call function to stop server in event server example
- Other minor code cleanup and enhancements
* Mon Feb 13 2012 - drahn 0.12.1-1
- Determine the remote IP address of the remote before negotiate
- Validate library inputs more completely
- Fix assl_fatalx() memory corruption using va_list twice without va_copy
- General cleanup and fixes
* Fri Jan 06 2012 - davec 0.12.0-1
- Make low delay and throughput flags control DSCP for IPv6
- Add function to set a callback for log information
- Fix an issue with error reporting when getting address information
- Other minor code cleanup and enhancements
* Thu Oct 27 2011 - davec 0.11.0-1
- Annotate functions that do not return
- Several man page corrections
- Make failure messages consistent
- Add build versioning
- Other minor cleanup
* Wed Aug 31 2011 - dhill 0.10.2-1
- Rework SSL negotiation to take up to roughly 10 seconds
- Attempt a connection to each address returned by host lookup instead of just the first address returned
* Tue Jul 26 2011 - davec 0.10.1-1
- Improve portability
- Don't link against clens directly from library
- Minor cleanup
* Tue Jul 03 2011 - davec 0.10.0-1
- Create
