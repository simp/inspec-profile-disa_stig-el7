control 'SV-204516' do
  title 'The Red Hat Enterprise Linux operating system must audit all executions of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by
    unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern
    and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to
    detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system audits the execution of privileged functions using the following
    command:
    # grep -iw execve /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
    If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.
    If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.'
  desc 'fix', 'Configure the operating system to audit the execution of privileged functions.
    Add or update the following rules in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'legacy': ['V-72095', 'SV-86719']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000327-GPOS-00127'
  tag 'gid': 'V-204516'
  tag 'rid': 'SV-204516r603261_rule'
  tag 'stig_id': 'RHEL-07-030360'
  tag 'fix_id': 'F-4640r88741_fix'
  tag 'cci': ['CCI-002234']
  tag nist: ['AC-6 (9)']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'

  audit_syscalls = ['execve']

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
          expect(audit_rule.fields.flatten).to include('uid!=euid', 'gid!=egid', 'euid=0', 'egid=0')
          expect(audit_rule.key.uniq).to include('setuid', 'setgid')
        end
      end
    end
  end
end
