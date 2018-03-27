# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

control "V-72101" do
  title "All uses of the lchown command must be audited."
  desc  "
    Without generating audit records that are specific to the security and mission
needs of the organization, it would be difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
system (e.g., module or policy filter).

    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172,
SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-0021.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-72101"
  tag "rid": "SV-86725r2_rule"
  tag "stig_id": "RHEL-07-030390"
  tag "cci": ["CCI-000126","CCI-000172"]
  tag "nist": ["AU-2 d","AU-12 c","Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"lchown\" command occur.

Check the file system rules in \"/etc/audit/audit.rules\" with the following
commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit
architectures. Only the lines appropriate for the system architecture must be
present.

# grep -i lchown /etc/audit/audit.rules

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

If the command does not return any output, this is a finding."
  tag "fix": "Add or update the following rule in \"/etc/audit/rules.d/audit.rules\"
(removing those that do not match the CPU architecture):

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

The audit daemon must be restarted for the changes to take effect."

  describe auditd.syscall("lchown").where {arch == "b32"} do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall("lchown").where {arch == "b64"} do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
