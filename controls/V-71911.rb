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

control "V-71911" do
  title "When passwords are changed a minimum of eight of the total number of
characters must be changed."
  desc  "
    Use of a complex password helps to increase the time and resources required to
compromise the password. Password complexity, or strength, is a measure of the
effectiveness of a password in resisting attempts at guessing and brute-force
attacks.

    Password complexity is one factor of several that determines how long it takes
to crack a password. The more complex the password, the greater the number of
possible combinations that need to be tested before the password is compromised.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000072-GPOS-00040"
  tag "gid": "V-71911"
  tag "rid": "SV-86535r1_rule"
  tag "stig_id": "RHEL-07-010160"
  tag "cci": "CCI-000195"
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  tag "check": "The \"difok\" option sets the number of characters in a password
that must not be present in the old password.

Check for the value of the \"difok\" option in \"/etc/security/pwquality.conf\" with
the following command:

# grep difok /etc/security/pwquality.conf
difok = 8

If the value of \"difok\" is set to less than \"8\", this is a finding."
  tag "fix": "Configure the operating system to require the change of at least eight
of the total number of characters when passwords are changed by setting the
\"difok\" option.

Add the following line to \"/etc/security/pwquality.conf\" (or modify the line to
have the required value):

difok = 8"

  describe parse_config_file("/etc/security/pwquality.conf") do
    its('difok.to_i') { should cmp >= 8 }
  end
end
