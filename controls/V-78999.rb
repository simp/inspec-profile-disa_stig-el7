# encoding: utf-8
#
control "V-78999" do
  title "All uses of the create_module command must be audited."
  desc  "
    Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000471-GPOS-00216"
  tag "satisfies": ["SRG-OS-000471-GPOS-00216", "SRG-OS-000477-GPOS-00222"]
  tag "gid": "V-78999"
  tag "rid": "SV-93705r1_rule"
  tag "stig_id": "RHEL-07-030819"
  tag "cci": ["CCI-000172"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "subsystems": ["audit"]
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"create_module\" command occur.

Check the auditing rules in \"/etc/audit/audit.rules\" with the following
command:

Note: The output lines of the command are duplicated to cover both 32-bit and
64-bit architectures. Only the line appropriate for the system architecture
must be present.

# grep -iw create_module /etc/audit/audit.rules

If the command does not return the following output (appropriate to the
architecture), this is a finding.

-a always,exit -F arch=b32 -S create_module -k module-change

-a always,exit -F arch=b64 -S create_module -k module-change

If there are no audit rules defined for \"create_module\", this is a finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"create_module\" command occur.

Add or update the following rules in \"/etc/audit/rules.d/audit.rules\":

Note: The rules are duplicated to cover both 32-bit and 64-bit architectures.
Only the lines appropriate for the system architecture must be configured.

-a always,exit -F arch=b32 -S create_module -k module-change

-a always,exit -F arch=b64 -S create_module -k module-change

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-85749r1_fix"

  describe auditd.syscall("create_module").where {arch == "b32"} do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall("create_module").where {arch == "b64"} do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end

end
