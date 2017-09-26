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

control "V-71919" do
  title "The PAM system service must be configured to store only encrypted
representations of passwords."
  desc  "Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be plainly
read (i.e., clear text) and easily compromised. Passwords encrypted with a weak
algorithm are no more protected than if they are kept in plain text."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "gid": "V-71919"
  tag "rid": "SV-86543r1_rule"
  tag "stig_id": "RHEL-07-010200"
  tag "cci": "CCI-000196"
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "Verify the PAM system service is configured to store only encrypted
representations of passwords. The strength of encryption that must be used to hash
passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the
following command:

# grep password /etc/pam.d/system-auth-ac
password sufficient pam_unix.so sha512

If the \"/etc/pam.d/system-auth-ac\" configuration files allow for password hashes
other than SHA512 to be used, this is a finding."
  tag "fix": "Configure the operating system to store only SHA512 encrypted
representations of passwords.

Add the following line in \"/etc/pam.d/system-auth-ac\":

password sufficient pam_unix.so sha512

and run the \"authconfig\" command."

  describe file("/etc/pam.d/system-auth-ac") do
    its('content') { should match /^password\s+sufficient\s+pam_unix.so .*sha512.*$/ }
  end
end
