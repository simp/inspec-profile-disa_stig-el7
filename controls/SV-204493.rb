control 'SV-204493' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that a separate file system is used for
    user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a
    file system becoming full or failing.'
  tag 'legacy': ['SV-86683', 'V-72059']
  desc 'rationale', ''
  desc 'check', "Verify that a separate file system/partition has been created for non-privileged local interactive
    user home directories.
    Check the home directory assignment for all non-privileged users (those with a UID of 1000 or greater) on the system
    with the following command:
    # awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd
    adamsj 1000 /home/adamsj /bin/bash
    jacksonm 1001 /home/jacksonm /bin/bash
    smithj 1002 /home/smithj /bin/bash
    The output of the command will give the directory/partition that contains the home directories for the
    non-privileged users on the system (in this example, /home) and users' shell. All accounts with a valid shell (such
    as /bin/bash) are considered interactive users.
    Check that a file system/partition has been created for the non-privileged interactive users with the following
    command:
    Note: The partition of /home is used in the example.
    # grep /home /etc/fstab
    UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2
    If a separate entry for the file system/partition that contains the non-privileged interactive users' home
    directories does not exist, this is a finding."
  desc 'fix', 'Migrate the "/home" directory onto a separate file system/partition.'
  impact 0.3
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204493'
  tag 'rid': 'SV-204493r603840_rule'
  tag 'stig_id': 'RHEL-07-021310'
  tag 'fix_id': 'F-4617r88672_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  exempt_home_users = input('exempt_home_users')
  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  # excluding root because its home directory is usually "/root" (mountpoint "/")
  users.where { !shell.match(ignore_shells) && (uid >= uid_min) }.entries.each do |user_info|
    next if exempt_home_users.include?(user_info.username.to_s)

    home_mount = command(%(df #{user_info.home} --output=target | tail -1)).stdout.strip
    describe user_info.username do
      context 'with mountpoint' do
        context home_mount do
          it { should_not be_empty }
          it { should_not match(%r{^/$}) }
        end
      end
    end
  end
end
