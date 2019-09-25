# encoding: utf-8
#

exempt_home_users = attribute(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  value: []
)

non_interactive_shells = attribute(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  value: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync", "/bin/true"]
)

control "V-72059" do
  title "A separate file system must be used for user home directories (such as
/home or an equivalent)."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72059"
  tag "rid": "SV-86683r1_rule"
  tag "stig_id": "RHEL-07-021310"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['home_dirs', 'file_system']
  tag "check": "Verify that a separate file system/partition has been created
for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users (those with a
UID greater than 1000) on the system with the following command:

#cut -d: -f 1,3,6,7 /etc/passwd | egrep \":[1-4][0-9]{3}\" | tr \":\" \"\\t\"

adamsj /home/adamsj /bin/bash
jacksonm /home/jacksonm /bin/bash
smithj /home/smithj /bin/bash

The output of the command will give the directory/partition that contains the
home directories for the non-privileged users on the system (in this example,
/home) and users’ shell. All accounts with a valid shell (such as /bin/bash)
are considered interactive users.

Check that a file system/partition has been created for the non-privileged
interactive users with the following command:

Note: The partition of /home is used in the example.

# grep /home /etc/fstab
UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2

If a separate entry for the file system/partition that contains the
non-privileged interactive users' home directories does not exist, this is a
finding."
  tag "fix": "Migrate the \"/home\" directory onto a separate file
system/partition."
  tag "fix_id": "F-78411r1_fix"

  ignore_shells = non_interactive_shells.join('|')

  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  # excluding root because its home directory is usually "/root" (mountpoint "/")
  users.where{ !shell.match(ignore_shells) && (uid >= uid_min)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")

    home_mount = command(%(df #{user_info.home} --output=target | tail -1)).stdout.strip
    describe user_info.username do
      context 'with mountpoint' do
        context home_mount do
          it { should_not be_empty }
          it { should_not match(%r(^/$)) }
        end
      end
    end
  end
end
