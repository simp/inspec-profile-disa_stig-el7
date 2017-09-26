# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

control "V-72231" do
  title "The operating system must implement cryptography to protect the integrity
of Lightweight Directory Access Protocol (LDAP) communications."
  desc  "
    Without cryptographic integrity protections, information can be altered by
unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography enabling
distribution of the public key to verify the hash information while maintaining the
confidentiality of the key used to generate the hash.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-72231"
  tag "rid": "SV-86855r2_rule"
  tag "stig_id": "RHEL-07-040200"
  tag "cci": "CCI-001453"
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Verify the operating system implements cryptography to protect the
integrity of remote ldap access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used.

Check that the path to the X.509 certificate for peer authentication with the
following command:

# grep -i cacertfile /etc/pam_ldap.conf
tls_cacertfile /etc/openldap/ldap-cacert.pem

Verify the \"tls_cacertfile\" option points to a file that contains the trusted CA
certificate.

If this file does not exist, or the option is commented out or missing, this is a
finding."
  tag "fix": "Configure the operating system to implement cryptography to protect
the integrity of LDAP remote access sessions.

Set the \"tls_cacertfile\" option in \"/etc/pam_ldap.conf\" to point to the path for
the X.509 certificates used for peer authentication."

  describe parse_config_file('/etc/sysconfig/authconfig') do
    its('USELDAPAUTH') { should cmp 'yes' }
  end
  # @todo - pam resource - also dynamically find directory?
  describe command('grep -i cacertfile /etc/pam_ldap.conf') do
    its('stdout.strip') { should match /^tls_cacertfile \/etc\/openldap\/ldap-cacert.pem$/}
  end
  describe file('/etc/openldap/ldap-cacert.pem') do
    it { should exist }
    it { should be_file }
  end
end
