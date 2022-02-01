control 'SV-204555' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the postqueue command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough
    information.
    At a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization
    must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of
    compromise.
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  tag 'legacy': ['SV-86801', 'V-72177']
  tag 'rationale': ''
  tag 'check': 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "postqueue" command occur.
    Check that the following system call is being audited by performing the following command to check the file system
    rules in "/etc/audit/audit.rules":
    # grep -iw /usr/sbin/postqueue /etc/audit/audit.rules
    -a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -k privileged-postfix
    If the command does not return any output, this is a finding.'
  tag 'fix': 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "postqueue" command occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -k privileged-postfix
    The audit daemon must be restarted for the changes to take effect.'
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000042-GPOS-00020'
  tag 'satisfies': ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172']
  tag 'gid': 'V-204555'
  tag 'rid': 'SV-204555r603261_rule'
  tag 'stig_id': 'RHEL-07-030770'
  tag 'fix_id': 'F-4679r462661_fix'
  tag 'cci': ['CCI-000135', 'CCI-002884']
  tag nist: ['AU-3 (1)', 'MA-4 (1) (a)']

  audit_file = '/usr/sbin/postqueue'

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
