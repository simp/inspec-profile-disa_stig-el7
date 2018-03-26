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

control "V-72027" do
  title "All files and directories contained in local interactive user home
directories must have mode 0750 or less permissive."
  desc  "If a local interactive user files have excessive permissions, unintended
users may be able to access or modify them."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72027"
  tag "rid": "SV-86651r1_rule"
  tag "stig_id": "RHEL-07-020680"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all files and directories contained in a local interactive
user home directory, excluding local initialization files, have a mode of \"0750\".

Check the mode of all non-initialization files in a local interactive user home
directory with the following command:

Files that begin with a \".\" are excluded from this requirement.

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\".

# ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar  5 17:06 file3

If any files are found with a mode more permissive than \"0750\", this is a finding."
  tag "fix": "Set the mode on files and directories in the local interactive user
home directory with the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

# chmod 0750 /home/smithj/<file>"
  findings = []
  users.where{ uid >= 1000 and home != ""}.entries.each do |user_info|
    #Check for directories more permissive than 750 and files more permissive than 640.
    findings = findings + command("find #{user_info.home} -xdev ! -name '.*' -type d -perm /027 -o -type f -perm /133").stdout.split("\n")
  end
  describe findings do
    its ('length') { should == 0 }
  end
end
