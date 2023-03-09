control 'SV-204482' do
  title 'The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from
    being executed on file systems that are being imported via Network File System (NFS).'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner
    privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid"
    files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain
    unauthorized administrative access.'
  desc 'rationale', ''
  desc 'check', 'Verify file systems that are being NFS imported are configured with the "nosuid" option.
    Find the file system(s) that contain the directories being exported with the following command:
    # more /etc/fstab | grep nfs
    UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid 0 0
    If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a
    finding.
    Verify the NFS is mounted with the "nosuid" option:
    # mount | grep nfs | grep nosuid
    If no results are returned, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are being imported via
    NFS.'
  impact 0.5
  tag 'legacy': ['SV-86669', 'V-72045']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204482'
  tag 'rid': 'SV-204482r603261_rule'
  tag 'stig_id': 'RHEL-07-021020'
  tag 'fix_id': 'F-4606r88639_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['etc_fstab']
  tag 'host', 'container'

  nfs_systems = etc_fstab.nfs_file_systems.entries

  if !nfs_systems.nil? && !nfs_systems.empty?
    nfs_systems.each do |nfs_system|
      describe "Network File System mounted on #{nfs_system['mount_point']}" do
        subject { nfs_system }
        its('mount_options') { should include 'nosuid' }
      end
    end
  else
    describe 'No NFS file systems were found' do
      subject { nfs_systems.nil? || nfs_systems.empty? }
      it { should eq true }
    end
  end
end
