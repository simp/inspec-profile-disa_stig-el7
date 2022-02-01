control 'SV-204538' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the chcon command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    Audit records can be generated from various components within the information system (e.g., module or policy
    filter).
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  tag 'legacy': ['V-72139', 'SV-86763']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "chcon" command occur.
    Check the file system rule in "/etc/audit/audit.rules" with the following command:
    # grep -i /usr/bin/chcon /etc/audit/audit.rules
    -a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -k privileged-priv_change
    If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "chcon" command occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -k privileged-priv_change
    The audit daemon must be restarted for the changes to take effect.'
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000392-GPOS-00172'
  tag 'satisfies': ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209']
  tag 'gid': 'V-204538'
  tag 'rid': 'SV-204538r603261_rule'
  tag 'stig_id': 'RHEL-07-030580'
  tag 'fix_id': 'F-4662r462619_fix'
  tag 'cci': ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']

  audit_file = '/usr/bin/chcon'

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
