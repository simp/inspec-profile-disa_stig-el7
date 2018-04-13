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

# TODO ENHANCE: 1. this needs to be enhanced, to loop though all the users
# TODO 2. drop ones that have `gid` <= 999. I think If I read this right./s

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

control "V-72011" do
  title "All local interactive users must have a home directory assigned in the
/etc/passwd file."
  desc  "If local interactive users are not assigned a valid home directory, there
is no place for the storage and control of files they should own."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72011"
  tag "rid": "SV-86635r1_rule"
  tag "stig_id": "RHEL-07-020600"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify local interactive users on the system have a home directory
assigned.

Check for missing local interactive user home directories with the following command:

# pwck -r
user 'lp': directory '/var/spool/lpd' does not exist
user 'news': directory '/var/spool/news' does not exist
user 'uucp': directory '/var/spool/uucp' does not exist
user 'smithj': directory '/home/smithj' does not exist

Ask the System Administrator (SA) if any users found without home directories are
local interactive users. If the SA is unable to provide a response, check for users
with a User Identifier (UID) of 1000 or greater with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep \":[1-4][0-9]{2}$|:[0-9]{1,2}$\"

If any interactive users do not have a home directory assigned, this is a finding."

  tag "fix": "Assign home directories to all local interactive users that currently
do not have a home directory assigned."

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  interactive_users = users.where{ !shell.match(IGNORE_SHELLS) }

  interactive_users.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    describe directory(user_info.home) do
      it { should exist }
    end
  end
end
