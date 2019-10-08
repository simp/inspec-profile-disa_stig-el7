# encoding: utf-8
#
control "V-71905" do
  title "When passwords are changed or new passwords are established, the new
password must contain at least one lower-case character."
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
  tag "gtitle": "SRG-OS-000070-GPOS-00038"
  tag "gid": "V-71905"
  tag "rid": "SV-86529r4_rule"
  tag "stig_id": "RHEL-07-010130"
  tag "cci": ["CCI-000193"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "subsystems": ['pam', 'pwquality', 'password']
  desc "check", "Note: The value to require a number of lower-case characters to
be set is expressed as a negative number in \"/etc/security/pwquality.conf\".

Check the value for \"lcredit\" in \"/etc/security/pwquality.conf\" with the
following command:

# grep lcredit /etc/security/pwquality.conf
lcredit = -1

If the value of \"lcredit\" is not set to a negative value, this is a finding."
  desc "fix", "Configure the operating system to lock an account for the maximum
period when three unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the \"auth\" section of the
\"/etc/pam.d/system-auth-ac\" and \"/etc/pam.d/password-auth-ac\" files to match the
following lines:

Note: RHEL 7.3 and later allows for a value of \"never\" for \"unlock_time\". This is
an acceptable value but should be used with caution if availability is a concern.

auth        required       pam_faillock.so preauth silent audit deny=3
even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root
fail_interval=900 unlock_time=604800

and run the \"authconfig\" command."

  describe parse_config_file("/etc/security/pwquality.conf") do
    its('lcredit.to_i') { should cmp < 0 }
  end
end
