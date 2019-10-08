# encoding: utf-8
#

difok = input('difok', value: 8, description: 'The acceptable range of
values for difok which specifies the maximum number of characters that must
change when a password is changed.')

control "V-71911" do
  title "When passwords are changed a minimum of eight of the total number of
characters must be changed."
  desc  "
    Use of a complex password helps to increase the time and resources required
to compromise the password. Password complexity, or strength, is a measure of
the effectiveness of a password in resisting attempts at guessing and
brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000072-GPOS-00040"
  tag "gid": "V-71911"
  tag "rid": "SV-86535r1_rule"
  tag "stig_id": "RHEL-07-010160"
  tag "cci": ["CCI-000195"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  desc "check", "The \"difok\" option sets the number of characters in a
password that must not be present in the old password.

Check for the value of the \"difok\" option in \"/etc/security/pwquality.conf\"
with the following command:

# grep difok /etc/security/pwquality.conf
difok = 8

If the value of \"difok\" is set to less than \"8\", this is a finding."
  desc "fix", "Configure the operating system to require the change of at least
eight of the total number of characters when passwords are changed by setting
the \"difok\" option.

Add the following line to \"/etc/security/pwquality.conf\" (or modify the line
to have the required value):

difok = 8"
  tag "fix_id": "F-78263r1_fix"
  describe parse_config_file("/etc/security/pwquality.conf") do
    its('difok.to_i') { should cmp >= difok }
  end
end
