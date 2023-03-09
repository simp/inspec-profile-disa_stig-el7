control 'SV-204507' do
  title 'The Red Hat Enterprise Linux operating system must take appropriate action when the remote logging buffer
    is full.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
    Off-loading is a common process in information systems with limited audit storage capacity.
    One method of off-loading audit logs in Red Hat Enterprise Linux is with the use of the audisp-remote dameon.  When
    the remote buffer is full, audit logs will not be collected and sent to the central log server.'
  desc 'rationale', ''
  desc 'check', 'Verify the audisp daemon is configured to take an appropriate action when the internal queue is
    full:
    # grep "overflow_action" /etc/audisp/audispd.conf
    overflow_action = syslog
    If the "overflow_action" option is not "syslog", "single", or "halt", or the line is commented out, ask the System
    Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate
    what action that system takes when the internal queue is full.
    If there is no evidence the system is configured to off-load audit logs to a different system or storage media or,
    if the configuration does not take appropriate action when the internal queue is full, this is a finding.'
  desc 'fix', 'Edit the /etc/audisp/audispd.conf file and add or update the "overflow_action" option:
    overflow_action = syslog
    The audit daemon must be restarted for changes to take effect:
    # service auditd restart'
  impact 0.5
  tag 'legacy': ['V-81019', 'SV-95731']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000342-GPOS-00133'
  tag 'satisfies': ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'gid': 'V-204507'
  tag 'rid': 'SV-204507r603261_rule'
  tag 'stig_id': 'RHEL-07-030210'
  tag 'fix_id': 'F-36312r602646_fix'
  tag 'cci': ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag subsystems: ['audit', 'audisp']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  elsif file('/etc/audisp/audispd.conf').exist?
    describe parse_config_file('/etc/audisp/audispd.conf') do
      its('overflow_action') { should match(/syslog$|single$|halt$/i) }
    end
  else
    describe "File '/etc/audisp/audispd.conf' cannot be found. This test cannot be checked in a automated fashion and you must check it manually" do
      skip "File '/etc/audisp/audispd.conf' cannot be found. This check must be performed manually"
    end
  end
end
