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

control "V-72253" do
  title "The SSH daemon must be configured to only use Message Authentication Codes
(MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
  desc  "DoD information systems are required to use FIPS 140-2 approved
cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement
is SHA."
  impact 0.5

  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-72253"
  tag "rid": "SV-86877r2_rule"
  tag "stig_id": "RHEL-07-040400"
  tag "cci": "CCI-001453"
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH daemon is configured to only use MACs employing FIPS
140-2-approved ciphers.

Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system
cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.

Check that the SSH daemon is configured to only use MACs employing FIPS
140-2-approved ciphers with the following command:

# grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-256,hmac-sha2-512

If any ciphers other than \"hmac-sha2-256\" or \"hmac-sha2-512\" are listed or the
retuned line is commented out, this is a finding."
  tag "fix": "Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line
for the \"MACs\" keyword and set its value to \"hmac-sha2-256\" and/or
\"hmac-sha2-512\" (this file may be named differently or be in a different location
if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-256,hmac-sha2-512

The SSH service must be restarted for changes to take effect."

  # Must be either or both of these ciphers
  # TODO - replace with be_in when available
  describe.one do
    describe sshd_config do
      its('MACs') { should match /^hmac-sha2-256,hmac-sha2-512$/ }
    end
    describe sshd_config do
      its('MACs') { should match /^hmac-sha2-256$/ }
    end
    describe sshd_config do
      its('MACs') { should match /^hmac-sha2-512$/ }
    end
    describe sshd_config do
      its('MACs') { should match /^hmac-sha2-512,hmac-sha2-256$/ }
    end
  end
end
