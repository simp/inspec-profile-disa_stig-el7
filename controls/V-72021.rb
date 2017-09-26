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

control "V-72021" do
  title "All local interactive user home directories must be group-owned by the home
directory owners primary group."
  desc  "If the Group Identifier (GID) of a local interactive user’s home directory
is not the same as the primary GID of the user, this would allow unauthorized access
to the user’s files, and users that share the same group may not be able to access
files that they legitimately should."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72021"
  tag "rid": "SV-86645r2_rule"
  tag "stig_id": "RHEL-07-020650"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the assigned home directory of all local interactive users is
group-owned by that user’s primary GID.

Check the home directory assignment for all non-privileged users on the system with
the following command:

Note: This may miss local interactive users that have been assigned a privileged
UID. Evidence of interactive use may be obtained from a number of log files
containing system logon information.

# ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)
-rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj

Check the user's primary group with the following command:

# grep users /etc/group
users:x:250:smithj,jonesj,jacksons

If the user home directory referenced in \"/etc/passwd\" is not group-owned by that
user’s primary GID, this is a finding."
  tag "fix": "Change the group owner of a local interactive user’s home directory to
the group found in \"/etc/passwd\". To change the group owner of a local interactive
user’s home directory, use the following command:

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\", and has a primary group of users.

# chgrp users /home/smithj"

  # Assumption - users' home directories created in "home"
  home_dirs = command('ls -d /home/*').stdout.split("\n")
  home_dirs.each do |home|
    home_user = home.split("/")
    user_groups = command("groups #{home_user[2]}").stdout.split(" ")
    user_groups.delete_at(0)
    user_groups.delete_at(0)
    describe file("#{home}") do
      its('group') { should cmp "#{user_groups.first}" }
    end
  end
end
