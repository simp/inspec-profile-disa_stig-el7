control 'SV-204558' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the pam_timestamp_check command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it
    would be difficult to establish, correlate, and investigate the events relating to an incident or identify those
    responsible for one.
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  tag 'legacy': ['V-72185', 'SV-86809']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "pam_timestamp_check" command occur.
    Check the auditing rules in "/etc/audit/audit.rules" with the following command:
    # grep -iw "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules
    -a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -k privileged-pam
    If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "pam_timestamp_check" command occur.
    Add or update the following rule in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -k privileged-pam
    The audit daemon must be restarted for the changes to take effect.'
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000471-GPOS-00215'
  tag 'gid': 'V-204558'
  tag 'rid': 'SV-204558r603261_rule'
  tag 'stig_id': 'RHEL-07-030810'
  tag 'fix_id': 'F-4682r462670_fix'
  tag 'cci': ['CCI-000172']
  tag nist: ['AU-12 c']

  audit_file = '/sbin/pam_timestamp_check'

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
