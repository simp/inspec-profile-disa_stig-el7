# encoding: utf-8
#

# TODO update attrib to use the same `style` as the other PAM/PASSWD attributes
# TODO we should also have a PAM_PWQUALITY_PATH attrib I think

min_len = input('min_len', value: 15,
description: 'The minimum number of characters for passwords.')

control "V-71935" do
  title "Passwords must be a minimum of 15 characters in length."
  desc  "
    The shorter the password, the lower the number of possible combinations
that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
exponentially increase the time and/or resources required to compromise the
password.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000078-GPOS-00046"
  tag "gid": "V-71935"
  tag "rid": "SV-86559r1_rule"
  tag "stig_id": "RHEL-07-010280"
  tag "cci": ["CCI-000205"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  desc "check", "Verify the operating system enforces a minimum 15-character
password length. The \"minlen\" option sets the minimum number of characters in
a new password.

Check for the value of the \"minlen\" option in
\"/etc/security/pwquality.conf\" with the following command:

# grep minlen /etc/security/pwquality.conf
minlen = 15

If the command does not return a \"minlen\" value of 15 or greater, this is a
finding."
  desc "fix", "Configure operating system to enforce a minimum 15-character
password length.

Add the following line to \"/etc/security/pwquality.conf\" (or modify the line
to have the required value):

minlen = 15"
  tag "fix_id": "F-78287r1_fix"
  describe parse_config_file("/etc/security/pwquality.conf") do
    its('minlen.to_i') { should cmp >= min_len }
  end
end
