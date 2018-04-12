# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

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

control "V-72023" do
  title "All files and directories contained in local interactive user home
directories must be owned by the owner of the home directory."
  desc  "If local interactive users do not own the files in their directories,
unauthorized users may be able to access them. Additionally, if files are not owned
by the user, this could be an indication of system compromise."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72023"
  tag "rid": "SV-86647r1_rule"
  tag "stig_id": "RHEL-07-020660"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all files and directories in a local interactive user’s home
directory are owned by the user.

Check the owner of all files and directories in a local interactive user’s home
directory with the following command:

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\".

# ls -lLR /home/smithj
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3

If any files are found with an owner different than the home directory user, this is
a finding."
  tag "fix": "Change the owner of a local interactive user’s files and directories
to that owner. To change the owner of a local interactive user’s files and
directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\".

# chown smithj /home/smithj/<file or directory>"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')
  findings = Set[]
 print 
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    findings = findings + command("find #{user_info.home} -not -user #{user_info.username}").stdout.split("\n")
  end
  describe "Files and directories that are not owned by the user" do
    subject { findings.to_a }
     it { should be_empty }
  end
end
