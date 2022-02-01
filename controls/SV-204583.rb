control 'SV-204583' do
  title 'The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of
    Lightweight Directory Access Protocol (LDAP) communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without
    detection.
    Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash
    functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while
    maintaining the confidentiality of the key used to generate the hash.'
  tag 'legacy': ['SV-86855', 'V-72231']
  tag 'rationale': ''
  tag 'check': 'If LDAP is not being utilized, this requirement is Not Applicable.
    Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.
    To determine if LDAP is being used for authentication, use the following command:
    # systemctl status sssd.service
    sssd.service - System Security Services Daemon
    Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
    Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago
    If the "sssd.service" is "active", then LDAP is being used.
    Determine the "id_provider" that the LDAP is currently using:
    # grep -i "id_provider" /etc/sssd/sssd.conf
    id_provider = ad
    If "id_provider" is set to "ad", this is Not Applicable.
    Check the path to the X.509 certificate for peer authentication with the following command:
    # grep -i tls_cacert /etc/sssd/sssd.conf
    ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt
    Verify the "ldap_tls_cacert" option points to a file that contains the trusted CA certificate.
    If this file does not exist, or the option is commented out or missing, this is a finding.'
  tag 'fix': 'Configure the operating system to implement cryptography to protect the integrity of LDAP remote
    access sessions.
    Add or modify the following line in "/etc/sssd/sssd.conf":
    ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000250-GPOS-00093'
  tag 'gid': 'V-204583'
  tag 'rid': 'SV-204583r603261_rule'
  tag 'stig_id': 'RHEL-07-040200'
  tag 'fix_id': 'F-4707r88942_fix'
  tag 'cci': ['CCI-001453']
  tag nist: ['AC-17 (2)']

  sssd_id_ldap_enabled = (package('sssd').installed? and
    !command('grep "^\s*id_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  sssd_ldap_enabled = (package('sssd').installed? and
    !command('grep "^\s*[a-z]*_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  pam_ldap_enabled = !command('grep "^[^#]*pam_ldap\.so" /etc/pam.d/*').stdout.strip.empty?

  unless sssd_id_ldap_enabled or sssd_ldap_enabled or pam_ldap_enabled
    impact 0.0
    describe 'LDAP not enabled' do
      skip 'LDAP not enabled using any known mechanisms, this control is Not Applicable.'
    end
  end

  if sssd_id_ldap_enabled
    ldap_id_use_start_tls = command('grep ldap_id_use_start_tls /etc/sssd/sssd.conf')
    describe ldap_id_use_start_tls do
      its('stdout.strip') { should match(/^ldap_id_use_start_tls\s*=\s*true$/) }
    end

    ldap_id_use_start_tls.stdout.strip.each_line do |line|
      describe line do
        it { should match(/^ldap_id_use_start_tls\s*=\s*true$/) }
      end
    end
  end

  if sssd_ldap_enabled
    ldap_tls_cacert = command('grep -i ldap_tls_cacert /etc/sssd/sssd.conf')
                      .stdout.strip.scan(/^ldap_tls_cacert\s*=\s*(.*)/).last

    describe 'ldap_tls_cacert' do
      subject { ldap_tls_cacert }
      it { should_not eq nil }
    end

    unless ldap_tls_cacert.nil?
      describe file(ldap_tls_cacert.last) do
        it { should exist }
        it { should be_file }
      end
    end
  end

  if pam_ldap_enabled
    tls_cacertfile = command('grep -i tls_cacertfile /etc/pam_ldap.conf')
                     .stdout.strip.scan(/^tls_cacertfile\s+(.*)/).last

    describe 'tls_cacertfile' do
      subject { tls_cacertfile }
      it { should_not eq nil }
    end

    unless tls_cacertfile.nil?
      describe file(tls_cacertfile.last) do
        it { should exist }
        it { should be_file }
      end
    end
  end
end
