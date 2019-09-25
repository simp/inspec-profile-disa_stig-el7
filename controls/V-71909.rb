# encoding: utf-8
#
control "V-71909" do
  title "When passwords are changed or new passwords are assigned, the new
password must contain at least one special character."
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
  tag "gtitle": "SRG-OS-000266-GPOS-00101"
  tag "gid": "V-71909"
  tag "rid": "SV-86533r1_rule"
  tag "stig_id": "RHEL-07-010150"
  tag "cci": ["CCI-001619"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  tag "check": "Verify the operating system enforces password complexity by
requiring that at least one special character be used.

Note: The value to require a number of special characters to be set is
expressed as a negative number in \"/etc/security/pwquality.conf\".

Check the value for \"ocredit\" in \"/etc/security/pwquality.conf\" with the
following command:

# grep ocredit /etc/security/pwquality.conf
ocredit=-1

If the value of \"ocredit\" is not set to a negative value, this is a finding."
  tag "fix": "Configure the operating system to enforce password complexity by
requiring that at least one special character be used by setting the
\"dcredit\" option.

Add the following line to \"/etc/security/pwquality.conf\" (or modify the line
to have the required value):

ocredit = -1"
  tag "fix_id": "F-78261r1_fix"
  describe parse_config_file("/etc/security/pwquality.conf") do
    its('ocredit.to_i') { should cmp < 0 }
end
end
