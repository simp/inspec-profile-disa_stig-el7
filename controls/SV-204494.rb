control 'SV-204494' do
  title 'The Red Hat Enterprise Linux operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a
    file system becoming full or failing.'
  desc 'rationale', ''
  desc 'check', 'Verify that a separate file system/partition has been created for "/var".
    Check that a file system/partition has been created for "/var" with the following command:
    # grep /var /etc/fstab
    UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2
    If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  tag 'legacy': ['V-72061', 'SV-86685']
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204494'
  tag 'rid': 'SV-204494r603261_rule'
  tag 'stig_id': 'RHEL-07-021320'
  tag 'fix_id': 'F-4618r88675_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['/var', 'file_system']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe etc_fstab.where { mount_point == '/var/log' } do
      it { should exist }
    end
  end
end
