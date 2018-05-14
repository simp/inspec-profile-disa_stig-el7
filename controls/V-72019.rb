# encoding: utf-8
#

EXEMPT_HOME_USERS = attribute(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  default: []
)

NON_INTERACTIVE_SHELLS = attribute(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  default: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync"]
)

control "V-72019" do
  title "All local interactive user home directories must be owned by their
respective users."
  desc  "If a local interactive user does not own their home directory,
unauthorized users could access or modify the user's files, and the users may
not be able to access their own files."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72019"
  tag "rid": "SV-86643r4_rule"
  tag "stig_id": "RHEL-07-020640"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the assigned home directory of all local interactive
users on the system exists.

Check the home directory assignment for all local interactive users on the
system with the following command:

# ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

If any home directories referenced in \"/etc/passwd\" are not owned by the
interactive user, this is a finding."
  tag "fix": "Change the owner of a local interactive user’s home directories
to that owner. To change the owner of a local interactive user’s home
directory, use the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\".

# chown smithj /home/smithj"
  tag "fix_id": "F-78371r1_fix"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  findings = Set[]
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    describe directory(user_info.home) do
      it { should exist }
      its('owner') { should eq user_info.username }
    end
  end
end

