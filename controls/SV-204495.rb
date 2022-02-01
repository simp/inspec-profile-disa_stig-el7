control 'SV-204495' do
  title 'The Red Hat Enterprise Linux operating system must use a separate file system for the system audit data
    path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a
    file system becoming full or failing.'
  tag 'legacy': ['SV-86687', 'V-72063']
  tag 'rationale': ''
  tag 'check': 'Determine if the operating system is configured to have the "/var/log/audit" path is on a separate
    file system.
    # grep /var/log/audit /etc/fstab
    If no result is returned, or the operating system is not configured to have "/var/log/audit" on a separate file
    system, this is a finding.
    Verify that "/var/log/audit" is mounted on a separate file system:
    # mount | grep "/var/log/audit"
    If no result is returned, or "/var/log/audit" is not on a separate file system, this is a finding.'
  tag 'fix': 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204495'
  tag 'rid': 'SV-204495r603261_rule'
  tag 'stig_id': 'RHEL-07-021330'
  tag 'fix_id': 'F-4619r88678_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  describe mount('/var/log/audit') do
    it { should be_mounted }
  end
end
