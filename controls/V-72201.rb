# encoding: utf-8
#
control "V-72201" do
  title "All uses of the renameat command must be audited."
  desc  "If the system is not configured to audit certain activities and write
them to an audit log, it is more difficult to detect and track system
compromises and damages incurred during a system compromise."
  impact 0.5
  tag "gtitle": "SRG-OS-000466-GPOS-00210"
  tag "satisfies": ["SRG-OS-000466-GPOS-00210", "SRG-OS-000467-GPOS-00210",
"SRG-OS-000468-GPOS-00212", "SRG-OS-000392-GPOS-00172"]
  tag "gid": "V-72201"
  tag "rid": "SV-86825r3_rule"
  tag "stig_id": "RHEL-07-030890"
  tag "cci": ["CCI-000172", "CCI-002884"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"renameat\" command occur.

Check the file system rules in \"/etc/audit/audit.rules\" with the following
commands:

Note: The output lines of the command are duplicated to cover both 32-bit and
64-bit architectures. Only the lines appropriate for the system architecture
must be present.

# grep -iw renameat /etc/audit/audit.rules

-a always,exit -F arch=b32 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

-a always,exit -F arch=b64 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

If there are no audit rules defined for the \"renameat\" command, this is a
finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"renameat\" command occur.

Add the following rules in \"/etc/audit/rules.d/audit.rules\":

Note: The rules are duplicated to cover both 32-bit and 64-bit architectures.
Only the lines appropriate for the system architecture must be configured.

-a always,exit -F arch=b32 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

-a always,exit -F arch=b64 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-78555r6_fix"

  describe auditd.syscall("renameat").where {arch == "b32"} do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall("renameat").where {arch == "b64"} do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
