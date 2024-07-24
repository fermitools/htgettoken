Summary: Get OIDC bearer tokens by interacting with Hashicorp vault
Name: htgettoken
Version: 2.0
Release: 1%{?dist}

License: BSD-3-Clause
URL: https://github.com/fermitools/htgettoken

BuildArch: noarch
Prefix: %{_prefix}

# download with:
# $ curl -o htgettoken-%%{version}.tar.gz \
#    https://codeload.github.com/fermitools/htgettoken/tar.gz/%%{version}
Source0: %{name}-%{version}.tar.gz

# rpmbuild dependencies
BuildRequires: python-rpm-macros
BuildRequires: python3-rpm-macros

# build dependencies
BuildRequires: python3
BuildRequires: python%{python3_pkgversion}-pip
BuildRequires: python%{python3_pkgversion}-setuptools
BuildRequires: python%{python3_pkgversion}-wheel

# -- Package: htgettoken

# /usr/bin/htgettoken:
Requires: python%{python3_pkgversion}-gssapi
Requires: python%{python3_pkgversion}-paramiko
Requires: python%{python3_pkgversion}-urllib3
# /usr/bin/httokendecode:
Requires: jq
%if 0%{?rhel} && 0%{?rhel} >= 8
Recommends: scitokens-cpp
%endif

%description
htgettoken gets OIDC bearer tokens by interacting with Hashicorp vault

%files
%license COPYING
%doc README.md
%{_bindir}/*
%{_datadir}/man/man1/*
%{python3_sitelib}/*

# -- build steps

%prep
%autosetup -n %{name}-%{version}

%build
%py3_build

%install
# install the Python project
%py3_install
# link httokendecode to htdecodetoken
(cd %{buildroot}%{_bindir}/; ln -s htdecode httokendecode)
# install man pages
mkdir -p %{buildroot}%{_datadir}/man/man1
gzip -c %{name}.1 >%{buildroot}%{_datadir}/man/man1/%{name}.1.gz
for f in %{name} htdestroytoken htdecodetoken httokensh; do
    gzip -c $f.1 >%{buildroot}%{_datadir}/man/man1/$f.1.gz
done
ln -s htdecodetoken.1 %{buildroot}%{_datadir}/man/man1/httokendecode.1.gz 

%clean
rm -rf $RPM_BUILD_ROOT

# -- changelog

%changelog
* Wed Jul 24 2024 Dave Dykstra <dwd@fnal.gov> 2.0-1
- Replace use of m2crypto and pyOpenSSL with urllib3
- Replace use of pykerberos with gssapi
- Use standard Requires for Python modules instead of PyInstaller
- Add --vaultcertname option to specify an alternative certificate name.
  That used to be an additional optional meaning of the --vaultalias option,
  but urllib3 requires only one name to match.
- Add setuptools build infrastructure
- Refactor htgettoken script into module with entry point.
  This enables invoking htgettoken as `htgettoken.main()` from Python.
- Use wheels to build/install Python package, which simplified the entry
  points and improves (slightly) the metadata
- Fix the httokensh background process's check for its parent process.
  That is only a backup in case only the parent process is hard-killed,
  because normally the parent process kills the background process when
  the parent exits.
- Use newer `sts` secrets API for token exchanges.
- Fix the `-o`/`--outfile` option to work with relative paths. 
- Change the `--nobearertoken` option to always get and save a vault token.

* Thu Aug 17 2023 Dave Dykstra <dwd@fnal.gov> 1.20-1
- Update httokensh to by default set the minimum vault token time to live to
  6 days, and to make sure that the background refresh never gets a new vault
  token.
- Changed the preferred name of httokendecode to htdecodetoken, keeping
  links in the opposite direction.
- Add man pages for httokensh, htdestroytoken, and htdecodetoken.

* Thu Jul 27 2023 Dave Dykstra <dwd@fnal.gov> 1.19-1
- Add httokensh command.

* Wed May 24 2023 Dave Dykstra <dwd@fnal.gov> 1.18-1
- Fix crash introduced in 1.17 when using --nobearertoken while the
  credkey is not known.
- Make source rpm buildable on el9.

* Wed Mar 15 2023 Dave Dykstra <dwd@fnal.gov> 1.17-1
- Fix the usage of getaddrinfo, which caused a fatal error on python3.9
  on Mac.
- Make --showbearerurl work properly in combination with --nobearertoken.
- Change the httokendecode error message for a missing token file to
  stderr instead of stdin.

* Wed Oct 12 2022 Dave Dykstra <dwd@fnal.gov> 1.16-1
- Fix httokendecode -H functionality to only attempt to convert a parsed word
  if it is entirely numeric, not if it just contains one digit.  At the same
  time, rewrite the functionality in native bash instead of using grep and sed.
- Add htdestroytoken command.
- Add a symlink htdecodetoken pointing to httokendecode.

* Thu Jun 16 2022 Dave Dykstra <dwd@fnal.gov> 1.15-1
- Revert to prior method for allowing --vaultalias as an alternate name
  for matching the host cert.  It doesn't support wildcard certs, but it
  permits allowing either the original host name or the alias and avoids
  needing separate alias options for kerberos and https.

* Thu Jun 16 2022 Dave Dykstra <dwd@fnal.gov> 1.14-1
- Support wildcard host certs for all https connections.  They used to be
  supported for everything but the --vaultalias option but that support 
  was broken in version 1.13. 

* Thu Jun  9 2022 Dave Dykstra <dwd@fnal.gov> 1.13-2
- Suppress python warnings in order to avoid CryptographyDeprecationWarning
  about python3.6 being deprecated.

* Thu Jun  9 2022 Dave Dykstra <dwd@fnal.gov> 1.13-1
- Disable kerberos reverse DNS lookup in order to work when the vault
  server is using a DNS alias.
- Intelligently handle multiple IP addresses in a DNS name, timing out
  connection attempts after 5 seconds and not reusing addresses that
  failed to connect.  Tries IPv4 before IPv6.
- Update python dependencies to current versions in pip.

* Mon May 23 2022 Dave Dykstra <dwd@fnal.gov> 1.12-1
- Update htgettoken to allow utf-8 characters in messages.

* Wed Mar 30 2022 Dave Dykstra <dwd@fnal.gov> 1.11-1
- Update httokendecode to also validate the token if scitokens-verify is
  in $PATH. 

* Tue Feb 15 2022 Dave Dykstra <dwd@fnal.gov> 1.10-1
- Write out vault tokens after kerberos or ssh authentication only
  if they can successfully be used to read a bearer token
- Change the oidc authentication prompt to say to "copy/paste into any web
  browser" instead of "open URL manually"
- Update python dependencies to current versions in pip

* Fri Dec  3 2021 Dave Dykstra <dwd@fnal.gov> 1.9-1
- Add support for ssh-agent authentication, including the --sshpath, 
  --nossh and --registerssh options.  Add the paramiko package to the
  included library packages.
- Remove "/login" from --kerbpath.

* Fri Nov 19 2021 Dave Dykstra <dwd@fnal.gov> 1.8-1
- If kerberos initialization fails with the default KRB5_CONFIG="", try
  again without it.  Observed to be needed at CNAF, although not for
  FNAL, CERN, or LIGO.  Don't do second try if the first error was due
  to an expired ticket, because that sometimes erroneously succeeds on
  second try.

* Wed Nov 17 2021 Dave Dykstra <dwd@fnal.gov> 1.7-3
- Update version number to 1.7 in htgettoken

* Thu Nov  4 2021 Dave Dykstra <dwd@fnal.gov> 1.7-2
- Require jq for the sake of httokendecode

* Wed Nov  3 2021 Dave Dykstra <dwd@fnal.gov> 1.7-1
- Start using new vault secrets plugin feature that allows it to be shared
   between all issuers.  Requires htvault-config >= 1.5.
- Expand the --vaultalias option to also additionally allow that name
-  in vault's host certificate.
- Support finding python3 from PATH and not only /usr/bin
- Support python38
- Add httokendecode -H option
- Fix bug that caused traceback when handling an error writing the credkey
- Update python dependencies to current versions in pip

* Wed Sep 15 2021 Dave Dykstra <dwd@fnal.gov> 1.6-1
- Try a default cafile of '/etc/pki/tls/cert.pem' if system default is empty.
  This can happen when the SSL_CERT_FILE environment variable is empty.

* Tue Sep 14 2021 Dave Dykstra <dwd@fnal.gov> 1.5-1
- Add httokendecode command
- Add RELEASE_PROCEDURE file

* Mon Sep 13 2021 Dave Dykstra <dwd@fnal.gov> 1.4-1
- Add --vaulttokenminttl option
- Add --web-open-command option, and default it to xdg-open only when
  $SSH_CLIENT is not set
- Send the extra 'server' parameter recognized by htvault-config >= 1.5
  when --secretpath=secret/oauth/creds/%issuer/%credkey:%role, to use
  shared vault secrets instance (will be default later)
- Use the new pyinstaller 4.5 exclude_system_libraries() function instead
  of the previous hack to exclude system libraries from being bundled

* Tue Jul 13 2021 Dave Dykstra <dwd@fnal.gov> 1.3-1
- Add --kerbprincipal option
- Change the default kerbpath to include issuer and role
- Limit oidc polling to 2 minutes
- Disable oidc authentication when running in the background, that is, when
    none of stdin, stdout, or stderr are on a tty
- Document that audience can be a comma or space separated list
- Updated pip-installed dependent packages to latest versions

* Thu Apr  8 2021 Dave Dykstra <dwd@fnal.gov> 1.2-1
- Fix working with a kerberos domain that is missing from krb5.conf
- Extract more formatted information from http exceptions
- Improve format of printed kerberos exceptions

* Wed Dec 30 2020 Dave Dykstra <dwd@fnal.gov> 1.1-1
- Integrate with htcondor, including these changes:
 - Change --authpath option name to --oidcpath.
 - Add --noidc option.
 - Add --vaulttokenttl option.
 - Make --vaulttokenfile default to /dev/stdout if the ttl is more than
    a million seconds, and also require it to start with /dev/std or
    /dev/fd if the ttl is more than a million seconds.
 - Add --vaulttokeninfile option.
 - Add --nobearertoken option.
 - Add --showbearerurl option.
 - Send progress output to stderr if --vaulttokenfile is /dev/stdout or
     --showbearerurl option is enabled.
- Use a separate version number for the python library downloads tarball.

* Tue Dec 1 2020 Dave Dykstra <dwd@fnal.gov> 1.0-1
- Add --credkey option.
- Add --vaultalias option.
- Add --nokerberos and --kerbpath options.
- Change the name of the --vaultrole option to --role; the short name -r
   remains unchanged.
- Fill out the man page and add a html version of it to the source,
   generated by a Makefile.

* Mon Nov 2 2020 Dave Dykstra <dwd@fnal.gov> 0.5-1
- Set BROWSER variable to prevent xdg-open from running lynx, which hangs.

* Fri Oct 16 2020 Dave Dykstra <dwd@fnal.gov> 0.4-1
- Support the new poll api in addition to the old device_wait api when
  waiting for authorization response
- Use colon as separator in default secret path instead of hyphen
- Add --scopes and --audience options
- Implement the --minsecs option (was present before but didn't work)
- Stop reading old bearer token and remove use of jwt package

* Tue Jul 28 2020 Dave Dykstra <dwd@fnal.gov> 0.3-1
- Avoid including standard system libraries with pyinstaller
- Increase timeout on web browser interaction to 5 minutes
- Set up the interrupt signal to kill the program
- Add BuildRequires for openssl-devel and swig
- Remove confusing code for setting default cafile on RHEL and make setting
   the Debian default more clear

* Wed Jul 22 2020 Dave Dykstra <dwd@fnal.gov> 0.2-1
- Allow for missing xdg-open
- Add some missing "Exception as e" clauses
- Create configdir if missing when needed
- Change from jwt pip package to pyjwt, and disable verify_aud

* Tue Jul 21 2020 Dave Dykstra <dwd@fnal.gov> 0.1-1
- Initial release
