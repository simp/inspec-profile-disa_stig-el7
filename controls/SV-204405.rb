control 'SV-204405' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements
    /etc/pam.d/system-auth when changing passwords.'
  desc 'Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods.
    PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important
    security function could be bypassed if stack entries are not centralized.'
  desc 'rationale', ''
  desc 'check', 'Verify that /etc/pam.d/passwd is configured to use /etc/pam.d/system-auth when changing passwords:
    # cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth
    password     substack     system-auth
    If no results are returned, the line is commented out, this is a finding.'
  desc 'fix', 'Configure PAM to utilize /etc/pam.d/system-auth when changing passwords.
    Add the following line to "/etc/pam.d/passwd" (or modify the line to have the required value):
    password     substack    system-auth'
  impact 0.5
  tag 'legacy': ['SV-95715', 'V-81003']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000069-GPOS-00037'
  tag 'gid': 'V-204405'
  tag 'rid': 'SV-204405r603261_rule'
  tag 'stig_id': 'RHEL-07-010118'
  tag 'fix_id': 'F-4529r88408_fix'
  tag 'cci': ['CCI-000192']
  tag subsystems: ['pam', 'password']
  tag nist: ['IA-5 (1) (a)']
  tag 'host', 'container'

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('password substack system-auth') }
  end
end
