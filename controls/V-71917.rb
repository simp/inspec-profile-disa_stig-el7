# encoding: utf-8
#

#TODO make me an attrib

control "V-71917" do
  title "When passwords are changed the number of repeating characters of the
same character class must not be more than four characters."
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
  tag "gid": "V-71917"
  tag "rid": "SV-86541r1_rule"
  tag "stig_id": "RHEL-07-010190"
  tag "cci": ["CCI-000195"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  desc "check", "The \"maxclassrepeat\" option sets the maximum number of
allowed same consecutive characters in the same class in the new password.

Check for the value of the \"maxclassrepeat\" option in
\"/etc/security/pwquality.conf\" with the following command:

# grep maxclassrepeat /etc/security/pwquality.conf
maxclassrepeat = 4

If the value of \"maxclassrepeat\" is set to more than \"4\", this is a
finding."
  desc "fix", "Configure the operating system to require the change of the
number of repeating characters of the same character class when passwords are
changed by setting the \"maxclassrepeat\" option.

Add the following line to \"/etc/security/pwquality.conf\" conf (or modify the
line to have the required value):

maxclassrepeat = 4"
  tag "fix_id": "F-78269r1_fix"
  describe parse_config_file("/etc/security/pwquality.conf") do
    its('maxclassrepeat.to_i') { should cmp <= 4 }
  end
end
