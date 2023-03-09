control 'SV-204559' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the create_module syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "create_module" syscall occur.
    Check the auditing rules in "/etc/audit/audit.rules" with the following command:
    # grep -iw create_module /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S create_module -k module-change
    -a always,exit -F arch=b64 -S create_module -k module-change
    If both the "b32" and "b64" audit rules are not defined for the "create_module" syscall, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "create_module" syscall occur.
    Add or update the following rules in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S create_module -k module-change
    -a always,exit -F arch=b64 -S create_module -k module-change
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'legacy': ['V-78999', 'SV-93705']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000471-GPOS-00216'
  tag 'satisfies': ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'gid': 'V-204559'
  tag 'rid': 'SV-204559r603261_rule'
  tag 'stig_id': 'RHEL-07-030819'
  tag 'fix_id': 'F-4683r88870_fix'
  tag 'cci': ['CCI-000172']
  tag nist: ['AU-12 c']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'

  audit_syscalls = ['create_module']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  else
    describe 'Syscall' do
      audit_syscalls.each do |audit_syscall|
        it "#{audit_syscall} is audited properly" do
          audit_rule = auditd.syscall(audit_syscall)
          expect(audit_rule).to exist
          expect(audit_rule.action.uniq).to cmp 'always'
          expect(audit_rule.list.uniq).to cmp 'exit'
          if os.arch.match(/64/)
            expect(audit_rule.arch.uniq).to include('b32', 'b64')
          else
            expect(audit_rule.arch.uniq).to cmp 'b32'
          end
          expect(audit_rule.key.uniq).to cmp 'module-change'
        end
      end
    end
  end
end
