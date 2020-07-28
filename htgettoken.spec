Summary: Get OIDC bearer tokens by interacting with Hashicorp vault
Name: htgettoken
Version: 0.2
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

export PYTHONPATH="`echo $PYDIR/lib*/python*/site-packages|sed 's/ /:/g'`"
PYIOPTS="--noconsole --log-level=WARN"
$PYDIR/bin/pyi-makespec $PYIOPTS --specpath=dist %{name}
# This code was based on code found from
#  https://github.com/pyinstaller/pyinstaller/issues/2732#issuecomment-626325960
cat >dist/editlibs.spec <<!EOF!
def _should_include_binary(binary_tuple):
    path = binary_tuple[0]
    if not path.startswith('lib') or path.startswith('lib/'):
        return True
    if path.startswith('libpython') or path.startswith('libffi'):
        return True
    return False
a.binaries = list(filter(_should_include_binary, a.binaries))
!EOF!
awk '
    {if ($1 == "pyz") system("cat dist/editlibs.spec")}
    {print}
' dist/%{name}.spec >dist/%{name}-lesslibs.spec
$PYDIR/bin/pyinstaller $PYIOPTS --noconfirm --clean dist/%{name}-lesslibs.spec
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
#- Avoid including standard system libraries with pyinstaller

* Wed Jul 22 2020 Dave Dykstra <dwd@fnal.gov> 0.2-1
- Allow for missing xdg-open
- Add some missing "Exception as e" clauses
- Create configdir if missing when needed
- Change from jwt pip package to pyjwt, and disable verify_aud

* Tue Jul 21 2020 Dave Dykstra <dwd@fnal.gov> 0.1-1
- Initial release
