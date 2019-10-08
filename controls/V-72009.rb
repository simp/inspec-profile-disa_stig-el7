# encoding: utf-8
#

# TODO this should use a `finding` array and we should make sure it is nil right?

control "V-72009" do
  title "All files and directories must have a valid group owner."
  desc  "Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72009"
  tag "rid": "SV-86633r2_rule"
  tag "stig_id": "RHEL-07-020330"
  tag "cci": ["CCI-002165"]
  tag "documentable": false
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "subsystems": ['file_system', 'groups' ,'files']
  desc "check", "Verify all files and directories on the system have a valid
group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is
used as an example.

# find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding."
  desc "fix", "Either remove all files and directories from the system that do
not have a valid group, or assign a valid group to all files and directories on
the system with the \"chgrp\" command:

# chgrp <group> <file>"
  tag "fix_id": "F-78361r1_fix"

  command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'').
    stdout.strip.split("\n").each do |fs|
      describe command("find / -xautofs -fstype #{fs} -nogroup") do
        its('stdout.strip') { should be_empty }
      end
    end
end
