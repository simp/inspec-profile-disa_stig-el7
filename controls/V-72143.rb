# encoding: utf-8
#
skip_deprecated_test = input(
  'skip_deprecated_test',
  value: true,
  description: 'Skips test that have been deprecated and removed from the STIG.')

control "V-72143" do
  title "The operating system must generate audit records for all
successful/unsuccessful account access count events."
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
  tag "gid": "V-72143"
  tag "rid": "SV-86767r2_rule"
  tag "stig_id": "RHEL-07-030600"
  tag "cci": ["CCI-000126", "CCI-000172", "CCI-002884"]
  tag "documentable": false
  tag "nist": ["AU-2 d", "AU-12 c", "MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful account access count events occur.

Check the file system rule in \"/etc/audit/audit.rules\" with the following
commands:

# grep -i /var/log/tallylog /etc/audit/audit.rules

-w /var/log/tallylog -p wa -k logins

If the command does not return any output, this is a finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful account access count events occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-w /var/log/tallylog -p wa -k logins

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-78495r4_fix"

  audit_file = '/var/log/tallylog'

  if file(audit_file).exist?
    impact 0.5
  else
    impact 0.0
  end

  if skip_deprecated_test
    describe "This control has been deprecated out of the RHEL7 STIG. It will not be run becuase 'skip_deprecated_test' is set to True" do
      skip "This control has been deprecated out of the RHEL7 STIG. It will not be run becuase 'skip_deprecated_test' is set to True"
    end
  else
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
end
