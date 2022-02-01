control 'SV-204545' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the chage command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough
    information.
    At a minimum, the organization must audit the full-text recording of privileged password commands. The organization
    must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of
    compromise.
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  tag 'legacy': ['SV-86779', 'V-72155']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "chage" command occur.
    Check the file system rule in "/etc/audit/audit.rules" with the following command:
    # grep -i /usr/bin/chage /etc/audit/audit.rules
    -a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -k privileged-passwd
    If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "chage" command occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -k privileged-passwd
    The audit daemon must be restarted for the changes to take effect.'
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000042-GPOS-00020'
  tag 'satisfies': ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'gid': 'V-204545'
  tag 'rid': 'SV-204545r603261_rule'
  tag 'stig_id': 'RHEL-07-030660'
  tag 'fix_id': 'F-4669r462634_fix'
  tag 'cci': ['CCI-000135', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']

  audit_file = '/usr/bin/chage'

  if file(audit_file).exist?
    impact 0.5
  else
    impact 0.0
  end

  if file(audit_file).exist?
    describe auditd.file(audit_file) do
      its('permissions') { should include ['x'] }
      its('action') { should_not include 'never' }
    end
  end

  unless file(audit_file).exist?
    describe "The #{audit_file} file does not exist" do
      skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
    end
  end
end
