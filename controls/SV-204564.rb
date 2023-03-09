control 'SV-204564' do
  title 'The Red Hat Enterprise Linux operating system must generate audit records for all account creations,
    modifications, disabling, and termination events that affect /etc/passwd.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system must generate audit records for all account creations, modifications,
    disabling, and termination events that affect "/etc/passwd".
    Check the auditing rules in "/etc/audit/audit.rules" with the following command:
    # grep /etc/passwd /etc/audit/audit.rules
    -w /etc/passwd -p wa -k identity
    If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all account creations, modifications,
    disabling, and termination events that affect "/etc/passwd".
    Add or update the following rule "/etc/audit/rules.d/audit.rules":
    -w /etc/passwd -p wa -k identity
    The audit daemon must be restarted for the changes to take effect.'
  tag 'legacy': ['SV-86821', 'V-72197']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000004-GPOS-00004'
  tag 'satisfies': ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090',
                    'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221']
  tag 'gid': 'V-204564'
  tag 'rid': 'SV-204564r603261_rule'
  tag 'stig_id': 'RHEL-07-030870'
  tag 'fix_id': 'F-4688r88885_fix'
  tag 'cci': ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'

  audit_command = '/etc/passwd'

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
        expect(audit_rule.key).to cmp 'identity'
        expect(audit_rule.permissions.flatten).to include('w', 'a')
      end
    end
  end
end
