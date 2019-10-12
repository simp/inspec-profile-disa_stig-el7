# encoding: utf-8
#
skip_deprecated_test = input(
  'skip_deprecated_test',
  value: true,
  description: 'Skips test that have been deprecated and removed from the STIG.')

control "V-72169" do
  title "All uses of the sudoedit command must be audited."
  desc  "
    Reconstruction of harmful events or forensic analysis is not possible if
audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged access commands. The organization must maintain audit trails in
sufficient detail to reconstruct events to determine the cause and impact of
compromise.
  "
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "satisfies": ["SRG-OS-000037-GPOS-00015", "SRG-OS-000042-GPOS-00020",
"SRG-OS-000392-GPOS-00172", "SRG-OS-000462-GPOS-00206",
"SRG-OS-000471-GPOS-00215"]
  tag "gid": "V-72169"
  tag "rid": "SV-86793r4_rule"
  tag "stig_id": "RHEL-07-030730"
  tag "cci": ["CCI-000130", "CCI-000135", "CCI-000172", "CCI-002884"]
  tag "documentable": false
  tag "nist": ["AU-3", "AU-3 (1)", "AU-12 c", "MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"sudoedit\" command occur.

Check for the following system calls being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# grep -i \"/usr/bin/sudoedit\" /etc/audit/audit.rules

-a always,exit -F path=/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

If the command does not return any output, this is a finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"sudoedit\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect."
  tag "fix_id": "F-78523r4_fix"

  audit_file = '/bin/sudoedit'

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
        it { should include 'x' }
      end
    end if file(audit_file).exist?

    describe "The #{audit_file} file does not exist" do
      skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
    end if !file(audit_file).exist?
  end  
end
