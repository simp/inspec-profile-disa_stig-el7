control 'SV-204541' do
  title 'The Red Hat Enterprise Linux operating system must generate audit records for all successful account access
    events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful account access events occur.
    Check the file system rules in "/etc/audit/audit.rules" with the following commands:
    # grep -i /var/log/lastlog /etc/audit/audit.rules
    -w /var/log/lastlog -p wa -k logins
    If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful account access events occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -w /var/log/lastlog -p wa -k logins
    The audit daemon must be restarted for the changes to take effect.'
  tag 'legacy': ['V-72147', 'SV-86771']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000392-GPOS-00172'
  tag 'satisfies': ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214',
                    'SRG-OS-000473-GPOS-00218']
  tag 'gid': 'V-204541'
  tag 'rid': 'SV-204541r603261_rule'
  tag 'stig_id': 'RHEL-07-030620'
  tag 'fix_id': 'F-4665r88816_fix'
  tag 'cci': ['CCI-000126', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-2 d', 'AU-12 c', 'MA-4 (1) (a)']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'

  audit_command = '/var/log/lastlog'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  else
    describe 'Command' do
      it "#{audit_command} is audited properly" do
        audit_rule = auditd.file(audit_command)
        expect(audit_rule).to exist
        expect(audit_rule.key).to cmp 'logins'
        expect(audit_rule.permissions.flatten).to include('w', 'a')
      end
    end
  end
end
