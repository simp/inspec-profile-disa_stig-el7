control 'SV-204631' do
  title 'The Red Hat Enterprise Linux operating system must have the required packages for multifactor
    authentication installed.'

  desc 'Using an authentication device, such as a CAC or token that is separate from the information system, ensures
    that even if the information system is compromised, that compromise will not affect credentials stored on the
    authentication device.
    Multifactor solutions that require devices separate from information systems gaining access include, for example,
    hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S.
    Government Personal Identity Verification card and the DoD Common Access Card.
    A privileged account is defined as an information system account with authorizations of a privileged user.
    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system)
    communicating through an external, non-organization-controlled network. Remote access methods include, for example,
    dial-up, broadband, and wireless.
    This requirement only applies to components where this is specific to the function of the device or has the concept
    of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of
    configuring the device itself (management).'

  tag 'legacy': ['SV-87041', 'V-72417']
  desc 'check', 'Verify the operating system has the packages required for multifactor authentication installed.
    Check for the presence of the packages required to support multifactor authentication with the following commands:
    # yum list installed pam_pkcs11
    pam_pkcs11-0.6.2-14.el7.noarch.rpm
    If the "pam_pkcs11" package is not installed, this is a finding.'

  desc 'fix', 'Configure the operating system to implement multifactor authentication by installing the required
    packages.
    Install the pam_pkcs11 package with the following command:
    # yum install pam_pkcs11'

  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000375-GPOS-00160'
  tag 'satisfies': ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000375-GPOS-00161', 'SRG-OS-000375-GPOS-00162']
  tag 'gid': 'V-204631'
  tag 'rid': 'SV-204631r603261_rule'
  tag 'stig_id': 'RHEL-07-041001'
  tag 'fix_id': 'F-4755r462473_fix'
  tag 'cci': ['CCI-001948', 'CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (12)']

  mfa_pkg_list = input('mfa_pkg_list')
  smart_card_status = input('smart_card_status')

  if smart_card_status.eql?('disabled')
    impact 0.5
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable.'
    end
  elsif mfa_pkg_list.empty?
    describe 'The required Smartcard packages have not beed defined, plese define them in your `inputs`.' do
      subject { mfa_pkg_list }
      it { should_not be_empty }
    end
  else
    mfa_pkg_list.each do |pkg|
      describe 'The package' do
        subject { package(pkg.to_s) }
        it { should be_installed }
      end
    end
  end
end
