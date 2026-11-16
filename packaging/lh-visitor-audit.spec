Name:           lh-visitor-audit
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-visitor - Exponential Moving Average Rate of Scanners & Bot Signature
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-visitor-audit
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Web access telemetry and bot-forensics analyzer parsing HTTP/JSONL access logs to detect vulnerability scanners, directory brute-forcing, credential harvesters, and L7 DDoS anomalies.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-visitor ]; then
    install -m 0755 bin/lh-visitor %{buildroot}%{_bindir}/lh-visitor
elif [ -f lh-visitor ]; then
    install -m 0755 lh-visitor %{buildroot}%{_bindir}/lh-visitor
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
