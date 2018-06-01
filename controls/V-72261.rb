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

control "V-72261" do
  title "The SSH daemon must not permit Kerberos authentication unless needed."
  desc  "Kerberos authentication for SSH is often implemented using Generic Security
Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH,
the SSH daemon provides a means of access to the system's Kerberos implementation.
Vulnerabilities in the system's Kerberos implementation may then be subject to
exploitation. To reduce the attack surface of the system, the Kerberos
authentication mechanism within SSH must be disabled for systems not using this
capability."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000364-GPOS-00151"
  tag "gid": "V-72261"
  tag "rid": "SV-86885r2_rule"
  tag "stig_id": "RHEL-07-040440"
  tag "cci": "CCI-000318"
  tag "nist": ["CM-3 f", "Rev_4"]
  tag "cci": "CCI-000368"
  tag "nist": ["CM-6 c", "Rev_4"]
  tag "cci": "CCI-001812"
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "cci": "CCI-001813"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "cci": "CCI-001814"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH daemon does not permit Kerberos to authenticate
passwords unless approved.

Check that the SSH daemon does not permit Kerberos to authenticate passwords with
the following command:

# grep -i kerberosauth /etc/ssh/sshd_config
KerberosAuthentication no

If the \"KerberosAuthentication\" keyword is missing, or is set to \"yes\" and is
not documented with the Information System Security Officer (ISSO), or the returned
line is commented out, this is a finding."
  tag "fix": "Uncomment the \"KerberosAuthentication\" keyword in
\"/etc/ssh/sshd_config\" (this file may be named differently or be in a different
location if using a version of SSH that is provided by a third-party vendor) and set
the value to \"no\":

KerberosAuthentication no

The SSH service must be restarted for changes to take effect.

If Kerberos authentication is required, it must be documented, to include the
location of the configuration file, with the ISSO."

  describe sshd_config do
    its('KerberosAuthentication') { should cmp 'no' }
  end
end
