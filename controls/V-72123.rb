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

control "V-72123" do
  title "All uses of the `creat` command must be audited."
  desc  "Without generating audit records that are specific to the security and mission
        needs of the organization, it would be difficult to establish, correlate, and
        investigate the events relating to an incident or identify those responsible for one.

        Audit records can be generated from various components within the information
        system (e.g., module or policy filter)."

  impact 0.5

  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-72123"
  tag "rid": "SV-86747r2_rule"
  tag "stig_id": "RHEL-07-030500"
  tag "cci": ["CCI-000172","CCI-002884"]
  tag "nist": ["AU-12 c","MA-4 (1) (a)","Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"creat\" command occur.

Check the file system rules in \"/etc/audit/audit.rules\" with the following
commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit
architectures. Only the lines appropriate for the system architecture must be
present.

# grep -i creat /etc/audit/audit.rules

-a always,exit -F arch=b32 -S creat  -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295
-k access

-a always,exit -F arch=b64 -S creat  -F exit=-EACCES -F auid>=1000 -F
auid!=4294967295 -k access

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"creat\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\" (removing
those that do not match the CPU architecture):

-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295
-k access

-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F
auid!=4294967295 -k access

The audit daemon must be restarted for the changes to take effect."

  describe auditd.syscall("creat").where {arch == "b32"} do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
    its('exit.uniq') { should include '-EPERM' }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall("creat").where {arch == "b64"} do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('exit.uniq') { should include '-EACCES' }
    end
  end
end
