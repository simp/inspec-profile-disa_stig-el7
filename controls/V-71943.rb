# encoding: utf-8
#

UNSUCCESSFUL_ATTEMPTS = attribute('unsuccessful_attempts', default: 3,
description: 'The account is denied access after the specified number of
consecutive failed logon attempts.')
FAIL_INTERVAL = attribute('fail_interval', default: 900,
description: 'The interval of time in which the consecutive failed logon
attempts must occur in order for the account to be locked out.')
LOCKOUT_TIME = attribute('lockout_time', default: 604800,
description: 'The amount of time that an account must be locked out for
after the specified number of unsuccessful logon attempts.')

control "V-71943" do
  title "Accounts subject to three unsuccessful logon attempts within 15
minutes must be locked for the maximum configurable period."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-forcing, is reduced. Limits are imposed by locking the account."
  impact 0.5
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "satisfies": ["SRG-OS-000329-GPOS-00128", "SRG-OS-000021-GPOS-00005"]
  tag "gid": "V-71943"
  tag "rid": "SV-86567r3_rule"
  tag "stig_id": "RHEL-07-010320"
  tag "cci": ["CCI-002238"]
  tag "documentable": false
  tag "nist": ["AC-7 b", "Rev_4"]
  tag "subsystems": ['pam']
  tag "check": "Verify the operating system automatically locks an account for the
maximum period for which the system can be configured.

Check that the system locks an account for the maximum period after three
unsuccessful logon attempts within a period of 15 minutes with the following
command:

# grep pam_faillock.so /etc/pam.d/password-auth-ac
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800
account required pam_faillock.so

If the \"unlock_time\" setting is greater than \"604800\" on both lines with
the \"pam_faillock.so\" module name or is missing from a line, this is a
finding.

# grep pam_faillock.so /etc/pam.d/system-auth-ac
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800
account required pam_faillock.so

If the \"unlock_time\" setting is greater than \"604800\" on both lines with
the \"pam_faillock.so\" module name or is missing from a line, this is a
finding."
  tag "fix": "Configure the operating system to lock an account for the maximum
period when three unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the auth section of the
\"/etc/pam.d/system-auth-ac\" and \"/etc/pam.d/password-auth-ac\" files to
match the following lines:

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
account required pam_faillock.so"
  tag "fix_id": "F-78295r4_fix"
  only_if { file('/etc/pam.d/password-auth-ac').exist? && file('/etc/pam.d/system-auth-ac').exist?}

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS }
  end


  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL }
  end


  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME }
  end
end

