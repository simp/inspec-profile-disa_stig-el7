# encoding: utf-8
#
skip_deprecated_test = input(
  'skip_deprecated_test',
  value: true,
  description: 'Skips test that have been deprecated and removed from the STIG.')

control "V-72181" do
  title "All uses of the pt_chown command must be audited."
  desc  "
    Reconstruction of harmful events or forensic analysis is not possible if audit
records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of privileged
commands. The organization must maintain audit trails in sufficient detail to
reconstruct events to determine the cause and impact of compromise.

    Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172,
SRG-OS-000471-GPOS-0021.
  "
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000042-GPOS-00020"
  tag "gid": "V-72181"
  tag "rid": "SV-86805r2_rule"
  tag "stig_id": "RHEL-07-030790"
  tag "cci": "CCI-000135"
  tag "nist": ["AU-3 (1)", "Rev_4"]
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "cci": "CCI-002884"
  tag "nist": ["MA-4 (1) (a)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  desc "check", "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"pt_chown\" command occur.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# grep -i /usr/libexec/pt_chown /etc/audit/audit.rules

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged_terminal

If the command does not return any output, this is a finding."
  desc "fix", "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"pt_chown\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged_terminal

The audit daemon must be restarted for the changes to take effect."

  audit_file = '/usr/libexec/pt_chown'

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
