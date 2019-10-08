# encoding: utf-8
#

control "V-72231" do
  title "The operating system must implement cryptography to protect the
integrity of Lightweight Directory Access Protocol (LDAP) communications."
  desc  "
    Without cryptographic integrity protections, information can be altered by
unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the key used to generate the hash.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-72231"
  tag "rid": "SV-86855r2_rule"
  tag "stig_id": "RHEL-07-040200"
  tag "cci": ["CCI-001453"]
  tag "documentable": false
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "subsystems": ['sssd', 'ldap']
  desc "check", "Verify the operating system implements cryptography to protect
the integrity of remote ldap access sessions.

To determine if LDAP is being used for authentication, use the following
command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used.

Check that the path to the X.509 certificate for peer authentication with the
following command:

# grep -i cacertfile /etc/pam_ldap.conf
tls_cacertfile /etc/openldap/ldap-cacert.pem

Verify the \"tls_cacertfile\" option points to a file that contains the trusted
CA certificate.

If this file does not exist, or the option is commented out or missing, this is
a finding."
  desc "fix", "Configure the operating system to implement cryptography to
protect the integrity of LDAP remote access sessions.

Set the \"tls_cacertfile\" option in \"/etc/pam_ldap.conf\" to point to the
path for the X.509 certificates used for peer authentication."
  tag "fix_id": "F-78585r1_fix"

  sssd_id_ldap_enabled = (package('sssd').installed? and
    !command('grep "^\s*id_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  sssd_ldap_enabled = (package('sssd').installed? and
    !command('grep "^\s*[a-z]*_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  pam_ldap_enabled = (!command('grep "^[^#]*pam_ldap\.so" /etc/pam.d/*').stdout.strip.empty?)

  if !(sssd_id_ldap_enabled or sssd_ldap_enabled or pam_ldap_enabled)
    impact 0.0
    describe "LDAP not enabled" do
      skip "LDAP not enabled using any known mechanisms, this control is Not Applicable."
    end
  end

  if sssd_id_ldap_enabled
    ldap_id_use_start_tls = command('grep ldap_id_use_start_tls /etc/sssd/sssd.conf')
    describe ldap_id_use_start_tls do
      its('stdout.strip') { should match %r{^ldap_id_use_start_tls\s*=\s*true$}}
    end

    ldap_id_use_start_tls.stdout.strip.each_line do |line|
      describe line do
        it { should match %r{^ldap_id_use_start_tls\s*=\s*true$}}
      end
    end
  end

  if sssd_ldap_enabled
    ldap_tls_cacert = command('grep -i ldap_tls_cacert /etc/sssd/sssd.conf').
      stdout.strip.scan(%r{^ldap_tls_cacert\s*=\s*(.*)}).last

    describe "ldap_tls_cacert" do
      subject { ldap_tls_cacert }
      it { should_not eq nil }
    end

    describe file(ldap_tls_cacert.last) do
      it { should exist }
      it { should be_file }
    end if !ldap_tls_cacert.nil?
  end

  if pam_ldap_enabled
    tls_cacertfile = command('grep -i tls_cacertfile /etc/pam_ldap.conf').
      stdout.strip.scan(%r{^tls_cacertfile\s+(.*)}).last

    describe "tls_cacertfile" do
      subject { tls_cacertfile }
      it { should_not eq nil }
    end

    describe file(tls_cacertfile.last) do
      it { should exist }
      it { should be_file }
    end if !tls_cacertfile.nil?
  end
end
