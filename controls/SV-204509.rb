control 'SV-204509' do
  title 'The Red Hat Enterprise Linux operating system must off-load audit records onto a different system or media
    from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
    Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system off-loads audit records onto a different system or media from the system
    being audited.
    To determine the remote server that the records are being sent to, use the following command:
    # grep -i remote_server /etc/audisp/audisp-remote.conf
    remote_server = 10.0.21.1
    If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the
    audit logs are off-loaded to a different system or media.
    If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.'
  desc 'fix', 'Configure the operating system to off-load audit records onto a different system or media from the
    system being audited.
    Set the remote server option in "/etc/audisp/audisp-remote.conf" with the IP address of the log aggregation server.'
  impact 0.5
  tag 'legacy': ['V-72083', 'SV-86707']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000342-GPOS-00133'
  tag 'satisfies': ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'gid': 'V-204509'
  tag 'rid': 'SV-204509r603261_rule'
  tag 'stig_id': 'RHEL-07-030300'
  tag 'fix_id': 'F-4633r88720_fix'
  tag 'cci': ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag subsystems: ['audit', 'audisp']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  elsif file('/etc/audisp/audisp-remote.conf').exist?
    if input('audit_remote_server')
      describe parse_config_file('/etc/audisp/audisp-remote.conf') do
        its('remote_server'.to_s) { should cmp input('audit_remote_server') }
      end
    else
      describe parse_config_file('/etc/audisp/audisp-remote.conf') do
        its('remote_server'.to_s) { should match(/^\S+$/) }
        its('remote_server'.to_s) do
          should_not be_in ['localhost', '127.0.0.1']
        end
      end
    end
  else
    describe "File '/etc/audisp/audisp-remote.conf' cannot be found. This test cannot be checked in a automated fashion and you must check it manually" do
      skip "File '/etc/audisp/audisp-remote.conf' cannot be found. This check must be performed manually"
    end
  end
end
