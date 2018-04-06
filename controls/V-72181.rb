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

control "V-72181" do
  title "All uses of the `pt_chown` command must be audited."
  desc  "Reconstruction of harmful events or forensic analysis is not possible if audit
        records do not contain enough information.

        At a minimum, the organization must audit the full-text recording of privileged
        password commands. The organization must maintain audit trails in sufficient detail
        to reconstruct events to determine the cause and impact of compromise."

  impact 0.5

  tag "gtitle": "SRG-OS-000042-GPOS-00020"
  tag "gid": "V-72181"
  tag "rid": "SV-86805r2_rule"
  tag "stig_id": "RHEL-07-030790"
  tag "cci": ["CCI-000135","CCI-000172","CCI-002884"]
  tag "nist": ["AU-3 (1)","AU-12 c","MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"pt_chown\" command occur.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# grep -i /usr/libexec/pt_chown /etc/audit/audit.rules

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged_terminal

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"pt_chown\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged_terminal

The audit daemon must be restarted for the changes to take effect."

  @audit_file = '/usr/libexec/pt_chown'

  describe auditd.file(@audit_file) do
    its('permissions') { should_not cmp [] }
    its('action') { should_not include 'never' }
  end

  # Resource creates data structure including all usages of file
  @perms = auditd.file(@audit_file).permissions

  @perms.each do |perm|
    describe perm do
      it { should include 'x' }
    end
  end
  only_if { file(@audit_file).exist? }
end
