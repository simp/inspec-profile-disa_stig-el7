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

control "V-73173" do
  title "The operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect /etc/opasswd."
  desc  "
    Without generating audit records that are specific to the security and mission
needs of the organization, it would be difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
system (e.g., module or policy filter).
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000004-GPOS-00004"
  tag "gid": "V-73173"
  tag "rid": "SV-87825r2_rule"
  tag "stig_id": "RHEL-07-030874"
  tag "cci": ["CCI-000018","CCI-000172","CCI-001403","CCI-002130"]
  tag "nist": ["AC-2 (4)","AU-12 c","AC-2 (4)","AC-2 (4)","Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system must generate audit records for all
account creations, modifications, disabling, and termination events that affect
/etc/opasswd.

Check the auditing rules in \"/etc/audit/rules.d/audit.rules\" with the following
command:

# grep /etc/opasswd /etc/audit/rules.d/audit.rules

-w /etc/opasswd -p wa -k audit_rules_usergroup_modification

If the command does not return a line, or the line is commented out, this is a
finding."

  tag "fix": "Configure the operating system to generate audit records for all
account creations, modifications, disabling, and termination events that affect
/etc/opasswd.

Add or update the following file system rule in \"/etc/audit/rules.d/audit.rules\":

-w /etc/opasswd -p wa -k identity

The audit daemon must be restarted for the changes to take effect."

  @audit_file = '/etc/opasswd'

  describe auditd.file(@audit_file) do
    its('permissions') { should_not cmp [] }
    its('action') { should_not include 'never' }
  end

  # Resource creates data structure including all usages of file
  @perms = auditd.file(@audit_file).permissions

  @perms.each do |perm|
    describe perm do
      it { should include 'w' }
      it { should include 'a' }
    end
  end
  only_if { file(@audit_file).exist? }
end
