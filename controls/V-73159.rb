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

control "V-73159" do
  title "When passwords are changed or new passwords are established, pwquality must
be used."
  desc  "Use of a complex password helps to increase the time and resources required
to compromise the password. Password complexity, or strength, is a measure of the
effectiveness of a password in resisting attempts at guessing and brute-force
attacks. \"Pwquality\" enforces complex password construction configuration on the
system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000069-GPOS-00037"
  tag "gid": "V-73159"
  tag "rid": "SV-87811r2_rule"
  tag "stig_id": "RHEL-07-010119"
  tag "cci": "CCI-000192"
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  tag "check": "Verify the operating system uses \"pwquality\" to enforce the
password complexity rules.

Check for the use of \"pwquality\" with the following command:

# grep pwquality /etc/pam.d/passwd

password    required    pam_pwquality.so retry=3

If the command does not return a line containing the value \"pam_pwquality.so\",
this is a finding."
  tag "fix": "Configure the operating system to use \"pwquality\" to enforce
password complexity rules.

Add the following line to \"/etc/pam.d/passwd\" (or modify the line to have the
required value):

password    required    pam_pwquality.so retry=3"

  # @todo - pam resource
  describe pam('/etc/pam.d/passwd') do
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so')}
  end
end
