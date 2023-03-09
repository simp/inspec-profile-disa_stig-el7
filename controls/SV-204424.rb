control 'SV-204424' do
  title 'The Red Hat Enterprise Linux operating system must not allow accounts configured with blank or null
    passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that
    account. Accounts with empty passwords should never be used in operational environments.'
  desc 'rationale', ''
  desc 'check', 'To verify that null passwords cannot be used, run the following command:
    # grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth
    If this produces any output, it may be possible to log on with accounts with empty passwords.
    If null passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may
    be possible to log on to the account without authenticating.
    Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" to prevent
    logons with empty passwords.
    Note: Manual changes to the listed files may be overwritten by the "authconfig" program. The "authconfig" program
    should not be used to update the configurations listed in this requirement.'
  impact 0.7
  tag 'legacy': ['V-71937', 'SV-86561']
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204424'
  tag 'rid': 'SV-204424r809187_rule'
  tag 'stig_id': 'RHEL-07-010290'
  tag 'fix_id': 'F-4548r88465_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['pam', 'password']
  tag 'host', 'container'

  describe.one do
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should_not match_pam_rule('.* .* pam_unix.so nullok') }
    end
    describe pam('/etc/pam.d/password-auth') do
      its('lines') { should_not match_pam_rule('.* .* pam_unix.so nullok') }
    end
  end
end
