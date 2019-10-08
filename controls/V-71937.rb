# encoding: utf-8
#
control "V-71937" do
  title "The system must not have accounts configured with blank or null
passwords."
  desc  "If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-71937"
  tag "rid": "SV-86561r2_rule"
  tag "stig_id": "RHEL-07-010290"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['pam', 'password']
  desc "check", "To verify that null passwords cannot be used, run the following
command:

# grep nullok /etc/pam.d/system-auth-ac

If this produces any output, it may be possible to log on with accounts with
empty passwords.

If null passwords can be used, this is a finding."
  desc "fix", "If an account is configured for password authentication but does
not have an assigned password, it may be possible to log on to the account
without authenticating.

Remove any instances of the \"nullok\" option in \"/etc/pam.d/system-auth-ac\"
to prevent logons with empty passwords.

Note: Any updates made to \"/etc/pam.d/system-auth-ac\" may be overwritten by
the \"authconfig\" program. The \"authconfig\" program should not be used."
  tag "fix_id": "F-78289r2_fix"

  describe pam('/etc/pam.d') do
    its('lines') { should match_pam_rule('.* .* pam_unix.so').all_without_args('nullok') }
  end
end
