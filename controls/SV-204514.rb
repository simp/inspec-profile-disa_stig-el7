control 'SV-204514' do
  title 'The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and
    Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum
    audit record storage capacity is reached.'
  desc 'If security personnel are not notified immediately when the threshold for the repository maximum audit
    record storage capacity is reached, they are unable to expand the audit record storage capacity before records are
    lost.'
  tag 'legacy': ['V-72091', 'SV-86715']
  tag 'rationale': ''
  tag 'check': 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the
    allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
    Check what action the operating system takes when the threshold for the repository maximum audit record storage
    capacity is reached with the following command:
    # grep -i space_left_action  /etc/audit/auditd.conf
    space_left_action = email
    If the value of the "space_left_action" keyword is not set to "email", this is a finding.'
  tag 'fix': 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold
    for the repository maximum audit record storage capacity is reached.
    Uncomment or edit the "space_left_action" keyword in "/etc/audit/auditd.conf" and set it to "email".
    space_left_action = email'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000343-GPOS-00134'
  tag 'gid': 'V-204514'
  tag 'rid': 'SV-204514r603261_rule'
  tag 'stig_id': 'RHEL-07-030340'
  tag 'fix_id': 'F-4638r88735_fix'
  tag 'cci': ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left_action.downcase') { should cmp 'email' }
  end
end
