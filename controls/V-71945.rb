# encoding: utf-8
#

UNSUCCESSFUL_ATTEMPTS_ROOT = attribute('unsuccessful_attempts_root', default: 3,
description: 'The root account is denied access after the specified number of
consecutive failed logon attempts.')
FAIL_INTERVAL_ROOT = attribute('fail_interval_root', default: 900,
description: 'The interval of time in which the consecutive failed logon
attempts must occur in order for the root account to be locked out.')
LOCKOUT_TIME_ROOT = attribute('lockout_time_root', default: 604800,
description: 'The amount of time that an root account must be locked out for
after the specified number of unsuccessful logon attempts.')

control "V-71945" do
  title "If three unsuccessful root logon attempts within 15 minutes occur the
associated account must be locked."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-forcing, is reduced. Limits are imposed by locking the account."
  impact 0.5
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "satisfies": ["SRG-OS-000329-GPOS-00128", "SRG-OS-000021-GPOS-00005"]
  tag "gid": "V-71945"
  tag "rid": "SV-86569r2_rule"
  tag "stig_id": "RHEL-07-010330"
  tag "cci": ["CCI-002238"]
  tag "documentable": false
  tag "nist": ["AC-7 b", "Rev_4"]
  tag "subsystems": ['pam']
  tag "check": "Verify the operating system automatically locks the root
account until it is released by an administrator when three unsuccessful logon
attempts in 15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth-ac
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
account required pam_faillock.so

If the \"even_deny_root\" setting is not defined on both lines with the
\"pam_faillock.so\" module name, this is a finding.

# grep pam_faillock.so /etc/pam.d/system-auth-ac
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
account required pam_faillock.so

If the \"even_deny_root\" setting is not defined on both lines with the
\"pam_faillock.so\" module name, this is a finding."
  tag "fix": "Configure the operating system to automatically lock the root
account until the locked account is released by an administrator when three
unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the auth section of the
\"/etc/pam.d/system-auth-ac\" and \"/etc/pam.d/password-auth-ac\" files to
match the following lines:

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
account required pam_faillock.so

Note: Any updates made to \"/etc/pam.d/system-auth-ac\" and
\"/etc/pam.d/password-auth-ac\" may be overwritten by the \"authconfig\"
program. The \"authconfig\" program should not be used."
  tag "fix_id": "F-78297r2_fix"
  only_if { file('/etc/pam.d/password-auth-ac').exist? && file('/etc/pam.d/system-auth-ac').exist?}

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS_ROOT }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS_ROOT }
  end


  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL_ROOT }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL_ROOT }
  end


  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME_ROOT }
  end

  describe command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME_ROOT }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS_ROOT }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "deny\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= UNSUCCESSFUL_ATTEMPTS_ROOT }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL_ROOT }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "fail_interval\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp <= FAIL_INTERVAL_ROOT }
  end


  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME_ROOT }
  end

  describe command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$" | grep -Po "unlock_time\s*=\s*[0-9]+" | cut -d "=" -f2') do
    its('stdout.to_i') { should cmp >= LOCKOUT_TIME_ROOT }
  end


  describe "The `/etc/pam.d/password-auth-ac file`" do
    subject { command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$"') }
    its('stdout.strip') { should include 'even_deny_root' }
  end

  describe "The `/etc/pam.d/system-auth-ac file`" do
    subject { command('grep -Po "^auth\s+required\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$"') }
    its('stdout.strip') { should include 'even_deny_root' }
  end

  describe "The `/etc/pam.d/password-auth-ac file`" do
    subject { command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/password-auth-ac | grep -Po "(?<=pam_faillock.so).*$"') }
    its('stdout.strip') { should include 'even_deny_root' }
  end

  describe "The `/etc/pam.d/system-auth-ac file`" do
    subject { command('grep -Po "^auth\s+\[default=die\]\s+pam_faillock.so.*$" /etc/pam.d/system-auth-ac | grep -Po "(?<=pam_faillock.so).*$"') }
    its('stdout.strip') { should include 'even_deny_root' }
  end
end

