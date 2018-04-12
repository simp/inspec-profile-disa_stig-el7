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

control "V-72019" do
  title "All local interactive user home directories must be owned by their
respective users."
  desc  "If a local interactive user does not own their home directory, unauthorized
users could access or modify the user's files, and the users may not be able to
access their own files."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72019"
  tag "rid": "SV-86643r2_rule"
  tag "stig_id": "RHEL-07-020640"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the assigned home directory of all local interactive users on
the system exists.

Check the home directory assignment for all local interactive non-privileged users
on the system with the following command:

Note: This may miss interactive users that have been assigned a privileged UID.
Evidence of interactive use may be obtained from a number of log files containing
system logon information.

# ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)
-rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj

If any home directories referenced in \"/etc/passwd\" are returned as not defined,
this is a finding."
  tag "fix": "Change the owner of a local interactive user’s home directories to
that owner. To change the owner of a local interactive user’s home directory, use
the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\".

# chown smithj /home/smithj"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  findings = Set[]
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    if file(user_info.home).exist? == false
      findings << user_info.home
    end
  end
  describe "This user's home directory does not exist"  do
    subject { findings.to_a }
     it { should be_empty }
  end
end
