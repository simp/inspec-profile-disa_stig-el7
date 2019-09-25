# encoding: utf-8
#

#TODO make me an attrib

control "V-71913" do
  title "When passwords are changed a minimum of four character classes must be
changed."
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
  tag "gid": "V-71913"
  tag "rid": "SV-86537r1_rule"
  tag "stig_id": "RHEL-07-010170"
  tag "cci": ["CCI-000195"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  tag "check": "The \"minclass\" option sets the minimum number of required
classes of characters for the new password (digits, upper-case, lower-case,
others).

Check for the value of the \"minclass\" option in
\"/etc/security/pwquality.conf\" with the following command:

# grep minclass /etc/security/pwquality.conf
minclass = 4

If the value of \"minclass\" is set to less than \"4\", this is a finding."
  tag "fix": "Configure the operating system to require the change of at least
four character classes when passwords are changed by setting the \"minclass\"
option.

Add the following line to \"/etc/security/pwquality.conf conf\" (or modify the
line to have the required value):

minclass = 4"
  tag "fix_id": "F-78265r1_fix"
  describe parse_config_file("/etc/security/pwquality.conf") do
    its('minclass.to_i') { should cmp >= 4 }
  end
end
