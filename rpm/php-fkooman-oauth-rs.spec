%global composer_vendor  fkooman
%global composer_project oauth-rs

%global github_owner     fkooman
%global github_name      php-oauth-lib-rs

Name:       php-%{composer_vendor}-%{composer_project}
Version:    0.7.1
Release:    1%{?dist}
Summary:    Resource Server library for OAuth 2.0 services written in PHP

Group:      System Environment/Libraries
License:    ASL 2.0
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
BuildArch:  noarch

Provides:   php-composer(%{composer_vendor}/%{composer_project}) = %{version}

Requires:   php-composer(fkooman/oauth-common) >= 0.5.0
Requires:   php-composer(fkooman/oauth-common) < 0.6.0
Requires:   php-pear(guzzlephp.org/pear/Guzzle) >= 3.9.0
Requires:   php-pear(guzzlephp.org/pear/Guzzle) < 4.0

Requires:   php >= 5.3.3

%description
This is a library to implement an OAuth 2.0 resource server (RS). The library 
can be used by any service that wants to accept OAuth 2.0 bearer tokens.

%prep
%setup -qn %{github_name}-%{version}

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/php
cp -pr src/* ${RPM_BUILD_ROOT}%{_datadir}/php

%files
%defattr(-,root,root,-)
%dir %{_datadir}/php/%{composer_vendor}/OAuth/ResourceServer
%{_datadir}/php/%{composer_vendor}/OAuth/ResourceServer/*
%doc README.md CHANGES.md COPYING composer.json

%changelog
* Tue Sep 23 2014 François Kooman <fkooman@tuxed.net> - 0.7.1-1
- update to 0.7.1

* Fri Sep 12 2014 François Kooman <fkooman@tuxed.net> - 0.7.0-1
- initial package
