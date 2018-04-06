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

control "V-72163" do
  title "All uses of the `sudoers` command must be audited."
  desc  "Reconstruction of harmful events or forensic analysis is not possible if audit
        records do not contain enough information.

        At a minimum, the organization must audit the full-text recording of privileged
        password commands. The organization must maintain audit trails in sufficient detail
        to reconstruct events to determine the cause and impact of compromise."

  impact 0.5

  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "gid": "V-72163"
  tag "rid": "SV-86787r3_rule"
  tag "stig_id": "RHEL-07-030700"
  tag "cci": ["CCI-000130","CCI-000135","CCI-000172","CCI-002884"]
  tag "nist": ["AU-3","AU-3 (1)","AU-12 c","MA-4 (1) (a)","Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"sudoer\" command occur.

Check for modification of the following files being audited by performing the
following commands to check the file system rules in \"/etc/audit/audit.rules\":

# grep /etc/sudoers /etc/audit/audit.rules

-w /etc/sudoers -p wa -k privileged-actions

# grep /etc/sudoers.d /etc/audit/audit.rules

-w /etc/sudoers.d -p wa -k privileged-actions

If the commands do not return output that does not match the examples, this is a
finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"sudoer\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-w /etc/sudoers -p wa -k privileged-actions

-w /etc/sudoers.d -p wa -k privileged-actions

The audit daemon must be restarted for the changes to take effect."

  @audit_files = ['/etc/sudoers', '/etc/sudoers.d']

  @audit_files.each do |audit_file|
    describe auditd.file(audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    # Resource creates data structure including all usages of file
    @perms = auditd.file(audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'w' }
        it { should include 'a' }
      end
    end
    only_if { file(audit_file).exist? }
  end
end
