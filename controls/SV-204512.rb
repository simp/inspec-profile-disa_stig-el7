control 'SV-204512' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate
    action when there is an error sending audit records to a remote system.'
  desc 'Taking appropriate action when there is an error sending audit records to a remote system will minimize the
    possibility of losing audit records.
    One method of off-loading audit logs in Red Hat Enterprise Linux is with the use of the audisp-remote dameon.'
  desc 'rationale', ''
  desc 'check', 'Verify the action the operating system takes if there is an error sending audit records to a remote
    system.
    Check the action that takes place if there is an error sending audit records to a remote system with the following
    command:
    # grep -i network_failure_action /etc/audisp/audisp-remote.conf
    network_failure_action = syslog
    If the value of the "network_failure_action" option is not "syslog", "single", or "halt", or the line is commented
    out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage
    media, and to indicate the action taken if there is an error sending audit records to the remote system.
    If there is no evidence that the system is configured to off-load audit logs to a different system or storage media,
    or if the configuration does not take appropriate action if there is an error sending audit records to the remote
    system, this is a finding.'
  desc 'fix', 'Configure the action the operating system takes if there is an error sending audit records to a remote
    system.
    Uncomment the "network_failure_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single",
    or "halt".
    network_failure_action = syslog'
  impact 0.5
  tag 'legacy': ['V-73163', 'SV-87815']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000342-GPOS-00133'
  tag 'gid': 'V-204512'
  tag 'rid': 'SV-204512r603261_rule'
  tag 'stig_id': 'RHEL-07-030321'
  tag 'fix_id': 'F-36315r602655_fix'
  tag 'cci': ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag subsystems: ['audit', 'audisp']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  else
    describe parse_config_file('/etc/audisp/audisp-remote.conf') do
      its('network_failure_action'.to_s) { should cmp input('expected_network_failure_action') }
      its('network_failure_action'.to_s) { should be_in ['syslog', 'single', 'halt'] }
    end
  end
end
