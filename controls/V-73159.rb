# encoding: utf-8
#
MAX_RETRY = attribute('max_retry', default: 3,
description: 'The operating system must limit password
failures.')
control "V-73159" do
  title "When passwords are changed or new passwords are established, pwquality
must be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks. “pwquality” enforces complex password construction
configuration and has the ability to limit brute-force attacks on the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000069-GPOS-00037"
  tag "gid": "V-73159"
  tag "rid": "SV-87811r3_rule"
  tag "stig_id": "RHEL-07-010119"
  tag "cci": ["CCI-000192"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "check": "Verify the operating system uses \"pwquality\" to enforce the
password complexity rules.

Check for the use of \"pwquality\" with the following command:

#  cat /etc/pam.d/passwd | grep pam_pwquality

password required pam_pwquality.so retry=3

If the command does not return a line containing the value
\"pam_pwquality.so\", this is a finding.

If the value of “retry” is set to “0” or greater than “3”, this is a finding."
  tag "fix": "Configure the operating system to use \"pwquality\" to enforce
password complexity rules.

Add the following line to \"/etc/pam.d/passwd\" (or modify the line to have the
required value):

password    required    pam_pwquality.so retry=3

Note: The value of “retry” should be between “1” and “3”."
  tag "fix_id": "F-79605r2_fix"

  # @todo - pam resource
  max_retry_val = command("grep -Po '(?<=pam_pwquality.so ).*$' /etc/pam.d/passwd | grep -Po '[\s]*retry[\s]*=[0-9]+' | cut -d '=' -f2").stdout.strip
  if max_retry_val != ""
    describe max_retry_val.to_i do
      it { should be >= 1 }
      it { should be <= MAX_RETRY }
    end
  else 
    describe max_retry_val do
      it { should_not eq "" }
    end
  end 
  only_if { package('gnome-desktop3').installed? }
end

