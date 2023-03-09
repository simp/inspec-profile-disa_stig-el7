control 'SV-204515' do
  title 'The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and
    Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record
    storage capacity is reached.'
  desc 'If security personnel are not notified immediately when the threshold for the repository maximum audit
    record storage capacity is reached, they are unable to expand the audit record storage capacity before records are
    lost.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the
    threshold for the repository maximum audit record storage capacity is reached.
    Check what account the operating system emails when the threshold for the repository maximum audit record storage
    capacity is reached with the following command:
    # grep -i action_mail_acct  /etc/audit/auditd.conf
    action_mail_acct = root
    If the value of the "action_mail_acct" keyword is not set to "root" and other accounts for security personnel, this
    is a finding.'
  desc 'fix', 'Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold
    for the repository maximum audit record storage capacity is reached.
    Uncomment or edit the "action_mail_acct" keyword in "/etc/audit/auditd.conf" and set it to root and any other
    accounts associated with security personnel.
    action_mail_acct = root'
  impact 0.5
  tag 'legacy': ['V-72093', 'SV-86717']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000343-GPOS-00134'
  tag 'gid': 'V-204515'
  tag 'rid': 'SV-204515r603261_rule'
  tag 'stig_id': 'RHEL-07-030350'
  tag 'fix_id': 'F-4639r88738_fix'
  tag 'cci': ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag subsystems: ['audit', 'auditd']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  else
    describe auditd_conf do
      its('action_mail_acct') { should cmp 'root' }
    end
  end
end
