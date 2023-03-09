control 'SV-204466' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all local interactive user
    accounts, upon creation, are assigned a home directory.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and
    control of files they should own.'
  desc 'rationale', ''
  desc 'check', 'Verify all local interactive users on the system are assigned a home directory upon creation.
    Check to see if the system is configured to create home directories for local interactive users with the following
    command:
    # grep -i create_home /etc/login.defs
    CREATE_HOME yes
    If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out,
    this is a finding.'
  desc 'fix', 'Configure the operating system to assign home directories to all new local interactive users by
    setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.
    CREATE_HOME yes'
  impact 0.5
  tag 'legacy': ['V-72013', 'SV-86637']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204466'
  tag 'rid': 'SV-204466r603261_rule'
  tag 'stig_id': 'RHEL-07-020610'
  tag 'fix_id': 'F-4590r88591_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['login_defs']
  tag 'host', 'container'

  describe login_defs do
    its('CREATE_HOME') { should eq 'yes' }
  end
end
