# encoding: utf-8
#
control "V-72177" do
  title "All uses of the postqueue command must be audited."
  desc  "
    Reconstruction of harmful events or forensic analysis is not possible if
audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged postfix commands. The organization must maintain audit trails in
sufficient detail to reconstruct events to determine the cause and impact of
compromise.
  "
  tag "gtitle": "SRG-OS-000042-GPOS-00020"
  tag "satisfies": ["SRG-OS-000042-GPOS-00020", "SRG-OS-000392-GPOS-00172"]
  tag "gid": "V-72177"
  tag "rid": "SV-86801r2_rule"
  tag "stig_id": "RHEL-07-030770"
  tag "cci": ["CCI-000135", "CCI-002884"]
  tag "documentable": false
  tag "nist": ["AU-3 (1)", "MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"postqueue\" command occur.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# grep -i /usr/sbin/postqueue /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix

If the command does not return any output, this is a finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"postqueue\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-78531r4_fix"

  audit_file = '/usr/sbin/postqueue'

  if file(audit_file).exist?
    impact 0.5
  else
    impact 0.0
  end

  describe auditd.file(audit_file) do
    its('permissions') { should_not cmp [] }
    its('action') { should_not include 'never' }
  end if file(audit_file).exist?

  # Resource creates data structure including all usages of file
  perms = auditd.file(audit_file).permissions

  perms.each do |perm|
    describe perm do
      it { should include 'x' }
    end
  end if file(audit_file).exist?

  describe "The #{audit_file} file does not exist" do
    skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
  end if !file(audit_file).exist?
end
