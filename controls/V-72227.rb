# encoding: utf-8
#
control "V-72227" do
  title "The operating system must implement cryptography to protect the
integrity of Lightweight Directory Access Protocol (LDAP) authentication
communications."
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
  tag "gid": "V-72227"
  tag "rid": "SV-86851r2_rule"
  tag "stig_id": "RHEL-07-040180"
  tag "cci": ["CCI-001453"]
  tag "documentable": false
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "subsystems": ['sssd', 'ldap']
  desc "check", "Verify the operating system implements cryptography to protect
the integrity of remote LDAP authentication sessions.

To determine if LDAP is being used for authentication, use the following
command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used. To see if LDAP is configured to
use TLS, use the following command:

# grep -i ssl /etc/pam_ldap.conf
ssl start_tls

If the \"ssl\" option is not \"start_tls\", this is a finding."
  desc "fix", "Configure the operating system to implement cryptography to
protect the integrity of LDAP authentication sessions.

Set the USELDAPAUTH=yes in \"/etc/sysconfig/authconfig\".

Set \"ssl start_tls\" in \"/etc/pam_ldap.conf\"."
  tag "fix_id": "F-78581r1_fix"

  sssd_id_ldap_enabled = (package('sssd').installed? and
    !command('grep "^\s*id_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  pam_ldap_enabled = (!command('grep "^[^#]*pam_ldap\.so" /etc/pam.d/*').stdout.strip.empty?)

  if !(sssd_id_ldap_enabled or pam_ldap_enabled)
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

  if pam_ldap_enabled
    describe command('grep -i ssl /etc/pam_ldap.conf') do
      its('stdout.strip') { should match %r{^ssl start_tls$}}
    end
  end
end
