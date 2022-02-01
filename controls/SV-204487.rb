control 'SV-204487' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are
    group-owned by root, sys, bin, or an application group.'
  desc 'If a world-writable directory is not group-owned by root, sys, bin, or an application Group Identifier
    (GID), unauthorized users may be able to modify files created by others.
    The only authorized public directories are those temporary directories supplied with the system or those designed to
    be temporary file repositories. The setting is normally reserved for directories used by the system and by users for
    temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  tag 'legacy': ['V-72047', 'SV-86671']
  tag 'rationale': ''
  tag 'check': 'The following command will discover and print world-writable directories that are not group-owned by
    a system account, assuming only system accounts have a GID lower than 1000. Run it once for each local partition
    [PART]:
    # find [PART] -xdev -type d -perm -0002 -gid +999 -print
    If there is output, this is a finding.'
  tag 'fix': 'All directories in local partitions which are world-writable should be group-owned by root or another
    system account. If any world-writable directories are not group-owned by a system account, this should be
    investigated. Following this, the directories should be deleted or assigned to an appropriate group.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204487'
  tag 'rid': 'SV-204487r744106_rule'
  tag 'stig_id': 'RHEL-07-021030'
  tag 'fix_id': 'F-36308r602634_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  application_groups = input('application_groups')

  ww_dirs = Set[]
  partitions = etc_fstab.params.map { |partition| partition['file_system_type'] }.uniq
  partitions.each do |part|
    cmd = "find / -perm -002 -xdev -type d -fstype #{part} -exec ls -lLd {} \\;"
    ww_dirs += command(cmd).stdout.split("\n")
  end

  ww_dirs.to_a.each do |curr_dir|
    dir_arr = curr_dir.split(' ')
    describe file(dir_arr.last) do
      its('group') { should be_in ['root', 'sys', 'bin'] + application_groups }
    end
  end
end
