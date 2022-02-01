control 'V-72207' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the unlinkat syscall."
  desc  "If the system is not configured to audit certain activities and write
them to an audit log, it is more difficult to detect and track system
compromises and damages incurred during a system compromise.


  "
  desc 'rationale', ''
  desc 'check', "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"unlinkat\" syscall occur.

    Check the file system rules in \"/etc/audit/audit.rules\" with the
following commands:

    # grep -iw unlinkat /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k
delete

    -a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k
delete

    If both the \"b32\" and \"b64\" audit rules are not defined for the
\"unlinkat\" syscall, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"unlinkat\" syscall occur.

    Add the following rules in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k
delete

    -a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k
delete

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag satisfies: ['SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00210',
                  'SRG-OS-000468-GPOS-00212', 'SRG-OS-000392-GPOS-00172']
  tag gid: 'V-72207'
  tag rid: 'SV-86831r5_rule'
  tag stig_id: 'RHEL-07-030920'
  tag fix_id: 'F-78561r10_fix'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']

  describe auditd.syscall('unlinkat').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall('unlinkat').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
