# encoding: utf-8
#
control "V-72145" do
  title "The operating system must generate audit records for all unsuccessful
account access events."
  desc  "
    Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  tag "gtitle": "SRG-OS-000392-GPOS-00172"
  tag "satisfies": ["SRG-OS-000392-GPOS-00172", "SRG-OS-000470-GPOS-00214",
"SRG-OS-000473-GPOS-00218"]
  tag "gid": "V-72145"
  tag "rid": "SV-86769r3_rule"
  tag "stig_id": "RHEL-07-030610"
  tag "cci": ["CCI-000126", "CCI-000172", "CCI-002884"]
  tag "documentable": false
  tag "nist": ["AU-2 d", "AU-12 c", "MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
unsuccessful account access events occur.

Check the file system rule in \"/etc/audit/audit.rules\" with the following
commands:

# grep -i /var/run/faillock /etc/audit/audit.rules

-w /var/run/faillock -p wa -k logins

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
unsuccessful account access events occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-w /var/run/faillock -p wa -k logins

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-78497r4_fix"

  audit_file = '/var/run/faillock'

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
      it { should include 'w' }
      it { should include 'a' }
    end
  end if file(audit_file).exist?

  describe "The #{audit_file} file does not exist" do
    skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
  end if !file(audit_file).exist?
end
