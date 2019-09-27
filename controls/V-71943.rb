# encoding: utf-8
#

unsuccessful_attempts = input('unsuccessful_attempts', value: 3,
description: 'The account is denied access after the specified number of
consecutive failed logon attempts.')
fail_interval = input('fail_interval', value: 900,
description: 'The interval of time in which the consecutive failed logon
attempts must occur in order for the account to be locked out (in seconds).')
lockout_time = input('lockout_time', value: 604800,
description: 'The minimum amount of time that an account must be locked out
after the specified number of unsuccessful logon attempts (in seconds).
This attribute should never be set greater than 604800.')

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
  tag "subsystems": ['pam', 'faillock']
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

  required_rules = [
    'auth required pam_faillock.so unlock_time=.*',
    'auth sufficient pam_unix.so try_first_pass',
    'auth [default=die] pam_faillock.so unlock_time=.*'
  ]
  alternate_rules = [
    'auth required pam_faillock.so unlock_time=.*',
    'auth sufficient pam_sss.so forward_pass',
    'auth sufficient pam_unix.so try_first_pass',
    'auth [default=die] pam_faillock.so unlock_time=.*'
  ]

  describe pam('/etc/pam.d/password-auth') do
    its('lines') {
      should match_pam_rules(required_rules).exactly.or \
             match_pam_rules(alternate_rules).exactly
    }
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('deny', '<=', unsuccessful_attempts) }
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('fail_interval', '<=', fail_interval) }
    its('lines') {
      should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_args('unlock_time=(0|never)').or \
            (match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('unlock_time', '<=', 604800).and \
             match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('unlock_time', '>=', lockout_time))
    }
  end

  describe pam('/etc/pam.d/system-auth') do
    its('lines') {
      should match_pam_rules(required_rules).exactly.or \
             match_pam_rules(alternate_rules).exactly
    }
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('deny', '<=', unsuccessful_attempts) }
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('fail_interval', '<=', fail_interval) }
    its('lines') {
      should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_args('unlock_time=(0|never)').or \
            (match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('unlock_time', '<=', 604800).and \
             match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_integer_arg('unlock_time', '>=', lockout_time))
    }
  end
end
