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

control "V-72025" do
  title "All files and directories contained in local interactive user home
directories must be group-owned by a group of which the home directory owner is a
member."
  desc  "If a local interactive user’s files are group-owned by a group of which the
user is not a member, unintended users may be able to access them."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72025"
  tag "rid": "SV-86649r1_rule"
  tag "stig_id": "RHEL-07-020670"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all files and directories in a local interactive user home
directory are group-owned by a group the user is a member of.

Check the group owner of all files and directories in a local interactive user’s
home directory with the following command:

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\".

# ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with an owner different than the group home directory user,
check to see if the user is a member of that group with the following command:

# grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj
smithj:x:521:smithj

If the user is not a member of a group that group owns file(s) in a local
interactive user’s home directory, this is a finding."
  tag "fix": "Change the group of a local interactive user’s files and directories
to a group that the interactive user is a member of. To change the group owner of a
local interactive user’s files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

# chgrp users /home/smithj/<file>"

  #Get home directory from /etc/passwd. Check users with UID >= 1000.
  findings = []
  u = users.where{uid >= 1000 and home != ""}.entries
  #For each user, build and execute a find command that identifies files
  #that are not owned by a group the user is a member of.
  u.each do |user|
    find_args = "" 
    user.groups.each { |curr_group|
      find_args = find_args+"-not -group #{curr_group} "
    }
    findings = findings + command("find #{user.home} #{find_args}").stdout.split("\n")
  end
  #If there are any files in a home directory that are not owned by
  #a group that the user is a member of then report a finding and 
  #provide the offending files.
  describe findings do
    it { should be nil }
  end
end
