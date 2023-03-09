control 'SV-204531' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the creat, open, openat,
    open_by_handle_at, truncate, and ftruncate syscalls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.
    The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the
    system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect
    performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining
    syscalls into one rule whenever possible.'
  desc 'rationale', ''
  desc 'check', %q(Verify the operating system generates audit records upon successful/unsuccessful attempts to use the
    "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls.
    Check the file system rules in "/etc/audit/audit.rules" with the following commands:
    # grep 'open\|truncate\|creat' /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F
    auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000
    -F auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F
    auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000
    -F auid!=unset -k access
    If both the "b32" and "b64" audit rules are not defined for the "creat", "open", "openat", "open_by_handle_at",
    "truncate", and "ftruncate" syscalls, this is a finding.
    If the output does not produce rules containing "-F exit=-EPERM", this is a finding.
    If the output does not produce rules containing "-F exit=-EACCES", this is a finding.)
  desc 'fix', 'Configure the operating system to generate audit records upon successful/unsuccessful attempts to use
    the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls.
    Add or update the following rules in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F
    auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000
    -F auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F
    auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000
    -F auid!=unset -k access
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'legacy': ['SV-86749', 'V-72125']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000064-GPOS-00033'
  tag 'satisfies': ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205',
                    'SRG-OS-000392-GPOS-00172']
  tag 'gid': 'V-204531'
  tag 'rid': 'SV-204531r809815_rule'
  tag 'stig_id': 'RHEL-07-030510'
  tag 'fix_id': 'F-4655r809814_fix'
  tag 'cci': ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag subsystems: ['audit', 'auditd', 'audit_rule']
  tag 'host'
  audit_syscalls = ['creat', 'open', 'openat', 'open_by_handle_at', 'truncate', 'ftruncate']

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
          expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1', 'exit=-EACCES', 'exit=-EPERM')
          expect(audit_rule.key.uniq).to cmp 'access'
        end
      end
    end
  end
end
