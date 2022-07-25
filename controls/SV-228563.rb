control 'SV-228563' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are owned by root, sys, bin, or an application user.'
  desc  "If a world-writable directory is not owned by root, sys, bin, or an application User Identifier (UID), unauthorized users may be able to modify files created by others.\n\nThe only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag gid: 'V-228563'
  tag rid: 'SV-228563r744119_rule'
  tag stig_id: 'RHEL-07-021031'
  tag fix_id: 'F-19547r377220_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag subsystems: ["world_writable","ww_dirs"]
  tag 'host'
  tag check: "The following command will discover and print world-writable directories that are not owned by a system account, assuming only system accounts have a UID lower than 1000. Run it once for each local partition [PART]:\n\n# find [PART] -xdev -type d -perm -0002 -uid +999 -print\n\nIf there is output, this is a finding."
  tag fix: 'All directories in local partitions which are world-writable should be owned by root or another system account. If any world-writable directories are not owned by a system account, this should be investigated. Following this, the files should be deleted or assigned to an appropriate group.'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable to a container" do
      skip "Control not applicable to a container"
    end
  else 
    ww_dirs = Set[]
    partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq
    partitions.each do |part|
      cmd = "find #{part} -xdev -type d -perm -0002 -uid +999 -print"
      ww_dirs += command(cmd).stdout.split("\n")
    end

    describe 'List of world-writeable directories which are not owned by system accounts across all partitions' do
      subject { ww_dirs.to_a }
      it { should be_empty }
    end
  end
end
