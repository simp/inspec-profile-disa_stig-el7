control 'SV-204517' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the chown, fchown, fchownat, and
    lchown syscalls.'
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
  tag 'legacy': ['SV-86721', 'V-72097']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records upon successful/unsuccessful attempts to use the
    "chown", "fchown", "fchownat", and "lchown" syscalls.
    Check the file system rules in "/etc/audit/audit.rules" with the following commands:
    # grep chown /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
    If both the "b32" and "b64" audit rules are not defined for the "chown", "fchown", "fchownat", and "lchown"
    syscalls, this is a finding.'
  desc 'fix', 'Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000064-GPOS-00033'
  tag 'satisfies': ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203',
                    'SRG-OS-000474-GPOS-00219']
  tag 'gid': 'V-204517'
  tag 'rid': 'SV-204517r809570_rule'
  tag 'stig_id': 'RHEL-07-030370'
  tag 'fix_id': 'F-4641r809192_fix'
  tag 'cci': ['CCI-000126', 'CCI-000172']
  tag nist: ['AU-2 d', 'AU-12 c']

  describe auditd.syscall('chown').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall('chown').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
