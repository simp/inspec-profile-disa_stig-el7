# encoding: utf-8
#

exempt_home_users = input(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  value: []
)

non_interactive_shells = input(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  value: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync", "/bin/true"]
)

control "V-72029" do
  title "All local initialization files for interactive users must be owned by
the home directory user or root."
  desc  "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72029"
  tag "rid": "SV-86653r1_rule"
  tag "stig_id": "RHEL-07-020690"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['init_files']
  desc "check", "Verify all local initialization files for interactive users are
owned by the home directory user or root.

Check the owner on all local initialization files with the following command:

Note: The example will be for the \"smithj\" user, who has a home directory of
\"/home/smithj\".

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .bash_profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .profile

If any file that sets a local interactive user’s environment variables to
override the system is not owned by the home directory owner or root, this is a
finding."
  desc "fix", "Set the owner of the local initialization files for interactive
users to either the directory owner or root with the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chown smithj /home/smithj/.*"
  tag "fix_id": "F-78381r1_fix"

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")
    findings = findings + command("find #{user_info.home} -name '.*' -not -user #{user_info.username} -a -not -user root").stdout.split("\n")
  end
  describe "Files and Directories not owned by the user or root of the parent home directory" do
    subject { findings.to_a }
    it { should be_empty }
  end
end
