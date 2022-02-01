control 'SV-204572' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the unlink, unlinkat, rename,
    renameat, and rmdir syscalls.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more
    difficult to detect and track system compromises and damages incurred during a system compromise.
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.
    The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the
    system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect
    performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining
    syscalls into one rule whenever possible.'
  tag 'legacy': ['V-72205', 'SV-86829']
  tag 'rationale': ''
  tag 'check': %q(Verify the operating system generates audit records upon successful/unsuccessful attempts to use the
    "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls.
    Check the file system rules in "/etc/audit/audit.rules" with the following commands:
    # grep 'unlink\|rename\|rmdir' /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
    If both the "b32" and "b64" audit rules are not defined for the "unlink", "unlinkat", "rename", "renameat", and
    "rmdir" syscalls, this is a finding.)
  tag 'fix': 'Configure the operating system to generate audit records upon successful/unsuccessful attempts to use
    the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls.
    Add the following rules in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000466-GPOS-00210'
  tag 'satisfies': ['SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212',
                    'SRG-OS-000392-GPOS-00172']
  tag 'gid': 'V-204572'
  tag 'rid': 'SV-204572r809825_rule'
  tag 'stig_id': 'RHEL-07-030910'
  tag 'fix_id': 'F-4696r809824_fix'
  tag 'cci': ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']

  describe auditd.syscall('unlink').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall('unlink').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
