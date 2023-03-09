control 'SV-204563' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the kmod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "kmod" command occur.
    Check the auditing rules in "/etc/audit/audit.rules" with the following command:
    # grep -iw kmod /etc/audit/audit.rules
    -w /usr/bin/kmod -p x -F auid!=unset -k module-change
    If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "kmod" command occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -w /usr/bin/kmod -p x -F auid!=unset -k module-change
    The audit daemon must be restarted for the changes to take effect.'
  tag 'legacy': ['SV-86815', 'V-72191']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000471-GPOS-00216'
  tag 'satisfies': ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'gid': 'V-204563'
  tag 'rid': 'SV-204563r603261_rule'
  tag 'stig_id': 'RHEL-07-030840'
  tag 'fix_id': 'F-4687r462673_fix'
  tag 'cci': ['CCI-000172']
  tag nist: ['AU-12 c']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'

  audit_command = '/usr/bin/kmod'

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
        expect(audit_rule.key).to cmp 'module-change'
        expect(audit_rule.permissions.flatten).to cmp 'x'
        expect(audit_rule.fields.flatten).to include 'auid!=-1'
      end
    end
  end
end
