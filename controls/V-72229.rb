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

LDAP_CA_CERTDIR = attribute(
  'ldap_ca_certdir',
  default: '/etc/openldap/certs',
  description: "Certificate directory containing CA certificate for LDAP"
)

control "V-72229" do
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

  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-72229"
  tag "rid": "SV-86853r2_rule"
  tag "stig_id": "RHEL-07-040190"
  tag "cci": "CCI-001453"
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Verify the operating system implements cryptography to protect the
integrity of remote LDAP access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used.

Check for the directory containing X.509 certificates for peer authentication with
the following command:

# grep -i cacertdir /etc/pam_ldap.conf
tls_cacertdir /etc/openldap/certs

Verify the directory set with the \"tls_cacertdir\" option exists.

If the directory does not exist or the option is commented out, this is a finding."
  tag "fix": "Configure the operating system to implement cryptography to protect
the integrity of LDAP remote access sessions.

Set the \"tls_cacertdir\" option in \"/etc/pam_ldap.conf\" to point to the directory
that will contain the X.509 certificates for peer authentication.

Set the \"tls_cacertfile\" option in \"/etc/pam_ldap.conf\" to point to the path for
the X.509 certificates used for peer authentication."

  authconfig = parse_config_file('/etc/sysconfig/authconfig')

  USESSSD_ldap_enabled = (authconfig.params['USESSSD'].eql? 'yes' and
    !command('grep "^\s*id_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  USESSSDAUTH_ldap_enabled = (authconfig.params['USESSSDAUTH'].eql? 'yes' and
    !command('grep "^\s*[a-z]*_provider\s*=\s*ldap" /etc/sssd/sssd.conf').stdout.strip.empty?)

  USELDAPAUTH_ldap_enabled = (authconfig.params['USELDAPAUTH'].eql? 'yes')

  # @todo - verify best way to check this
  VAS_QAS_ldap_enabled = (package('vasclnt').installed? or service('vasd').installed?)

  if !(USESSSD_ldap_enabled or USESSSDAUTH_ldap_enabled or
       USELDAPAUTH_ldap_enabled or VAS_QAS_ldap_enabled)
    impact 0.0
    describe "LDAP not enabled" do
      skip "LDAP not enabled using any known mechanisms, this control is Not Applicable."
    end
  end

  if USESSSD_ldap_enabled
    ldap_id_use_start_tls = command('grep ldap_id_use_start_tls /etc/sssd/sssd.conf')
    describe ldap_id_use_start_tls do
      its('stdout.strip') { should match %r{^ldap_id_use_start_tls = true$}}
    end

    ldap_id_use_start_tls.stdout.strip.each_line do |line|
      describe line do
        it { should match %r{^ldap_id_use_start_tls = true$}}
      end
    end
  end

  if USESSSDAUTH_ldap_enabled
    describe command('grep -i ldap_tls_cacertdir /etc/sssd/sssd.conf') do
      its('stdout.strip') { should match %r{^ldap_tls_cacertdir = #{Regexp.escape(LDAP_CA_CERTDIR)}$}}
    end
    describe file(LDAP_CA_CERTDIR) do
      it { should exist }
      it { should be_directory }
    end
  end

  if USELDAPAUTH_ldap_enabled
    describe command('grep -i tls_cacertdir /etc/pam_ldap.conf') do
      its('stdout.strip') { should match %r{^tls_cacertdir #{Regexp.escape(LDAP_CA_CERTDIR)}$}}
    end
    describe file(LDAP_CA_CERTDIR) do
      it { should exist }
      it { should be_directory }
    end
  end

  # @todo - not sure how USELDAP is implemented and how it affects the system, so ignore for now

  if VAS_QAS_ldap_enabled
    describe command('grep ldap-gsssasl-security-layers /etc/opt/quest/vas/vas.conf') do
      its('stdout.strip') { should match %r{^ldap-gsssasl-security-layers = 0$}}
      its('stdout.strip.lines.length') { should eq 1 }
    end
  end
end
