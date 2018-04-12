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

control "V-72033" do
  title "All local initialization files must have mode 0740 or less permissive."
  desc  "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72033"
  tag "rid": "SV-86657r1_rule"
  tag "stig_id": "RHEL-07-020710"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that all local initialization files have a mode of \"0740\"
or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If any local initialization files have a mode more permissive than \"0740\", this is
a finding."
  tag "fix": "Set the mode of the local initialization files to \"0740\" with the
following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chmod 0740 /home/smithj/.<INIT_FILE>"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  findings = Set[]
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    findings = findings + command("find #{user_info.home} -xdev -maxdepth 1 -name '.*' -type f -perm /037").stdout.split("\n")
  end
  describe findings do
    it { should be_empty }
  end
end
