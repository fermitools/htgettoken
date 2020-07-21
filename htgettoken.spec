Summary: Get OIDC bearer tokens by interacting with Hashicorp vault
Name: htgettoken
Version: 0.1
Release: 1%{?dist}
License: BSD
Group: Applications/System
URL: https://github.com/fermitools/htgettoken
# download with:
# $ curl -o htgettoken-%{version}.tar.gz \
#    https://codeload.github.com/fermitools/htgettoken/tar.gz/%{version}
Source0: %{name}-%{version}.tar.gz
# recreate this with make-downloads
Source1: %{name}-downloads.tar.gz
BuildRequires: python3-pip
BuildRequires: python3-devel

%description
htgettoken gets OIDC bearer tokens by interacting with Hashicorp vault

# set nil out debug_package here to avoid stripping
%global debug_package %{nil}

# eliminate .buid-id links on el8, they make python packages clash
%global _build_id_links none

%prep
%setup -q
%setup -b 1 -n %{name}-downloads -q

%build
# starts out in htgettoken-downloads

# install in reverse order of their download (because dependency downloads
#   come after requested packages)
HOME=$PWD pip3 install --no-cache-dir --user $(echo $(find . -type f | grep -v "/.local"| tac))

PYDIR=$PWD/.local

cd ../%{name}-%{version}

PYTHONPATH="`echo $PYDIR/lib*/python*/site-packages|sed 's/ /:/g'`" $PYDIR/bin/pyinstaller --noconfirm --noconsole --clean --log-level=WARN %{name}
# "from M2Crypto import _m2crypto" gets confused without this:
mkdir -p dist/%{name}/M2Crypto
cd dist/%{name}/M2Crypto
ln -s ../_m2crypto* .
cd -
find dist/%{name} -name '*.*' ! -type d|xargs chmod -x


%install
# starts out in htgettoken-downloads
cd ../%{name}-%{version}

rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_datadir}/man/man1
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}/%{name}
cp -r dist/%{name} $RPM_BUILD_ROOT%{_libexecdir}
cat > $RPM_BUILD_ROOT%{_bindir}/%{name} <<'!EOF!'
#!/bin/bash
exec %{_libexecdir}/%{name}/%{name} "$@"
!EOF!
chmod +x $RPM_BUILD_ROOT%{_bindir}/%{name}
gzip -c %{name}.1 >$RPM_BUILD_ROOT%{_datadir}/man/man1/%{name}.1.gz

%clean
rm -rf $RPM_BUILD_ROOT

%files
%{_bindir}/%{name}
%{_libexecdir}/%{name}
%{_datadir}/man/man1/%{name}*


%changelog
* Tue Jul 21 2020 Dave Dykstra <dwd@fnal.gov> 0.1-1
- Initial release
