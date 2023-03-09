control 'SV-204420' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are
    restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed
    periodically. If the operating system does not limit the lifetime of passwords and force users to change their
    passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'rationale', ''
  desc 'check', 'If passwords are not being used for authentication, this is Not Applicable.
    Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.
    Check for the value of "PASS_MAX_DAYS" in "/etc/login.defs" with the following command:
    # grep -i pass_max_days /etc/login.defs
    PASS_MAX_DAYS 60
    If the "PASS_MAX_DAYS" parameter value is not 60 or less, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a 60-day maximum password lifetime restriction.
    Add the following line in "/etc/login.defs" (or modify the line to have the required value):
    PASS_MAX_DAYS     60'
  impact 0.5
  tag 'legacy': ['V-71929', 'SV-86553']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000076-GPOS-00044'
  tag 'gid': 'V-204420'
  tag 'rid': 'SV-204420r603261_rule'
  tag 'stig_id': 'RHEL-07-010250'
  tag 'fix_id': 'F-4544r88453_fix'
  tag 'cci': ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag subsystems: ['login_defs', 'password']
  tag 'host', 'container'

  if command("grep 'pam_unix.so' /etc/pam.d/system-auth | grep 'auth ' | grep 'optional'").stdout.empty? && command("grep 'pam_permit.so' /etc/pam.d/system-auth | grep 'auth ' | grep 'required'").stdout.empty?
    describe login_defs do
      its('PASS_MAX_DAYS') { should cmp input('pass_max_days') }
      its('PASS_MAX_DAYS') { should cmp <= input('max_pass_max_days') }
    end
  else
    impact 0.0
    describe 'The system is not using password for authentication' do
      skip 'The system is not using password for authentication, this control is Not Applicable.'
    end
  end
end
