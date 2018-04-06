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

control "V-72047" do
  title "All world-writable directories must be group-owned by root, sys, bin, or an
application group."
  desc  "
    If a world-writable directory has the sticky bit set and is not group-owned by a
privileged Group Identifier (GID), unauthorized users may be able to modify files
created by others.

    The only authorized public directories are those temporary directories supplied
with the system or those designed to be temporary file repositories. The setting is
normally reserved for directories used by the system and by users for temporary file
storage, (e.g., /tmp), and for directories requiring global read/write access.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72047"
  tag "rid": "SV-86671r1_rule"
  tag "stig_id": "RHEL-07-021030"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all world-writable directories are group-owned by root, sys,
bin, or an application group.

Check the system for world-writable directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used
as an example.

# find / -perm -002 -xdev -type d -fstype xfs -exec ls -ld {} \\;
drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue
drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm
drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp

If any world-writable directories are not owned by root, sys, bin, or an application
group associated with the directory, this is a finding."
  tag "fix": "Change the group of the world-writable directories to root with the
following command:

# chgrp root <directory>"

  # @todo - add option for app group associated with dir?
  ww_dirs = command('find / -xdev -perm -002 -type d -exec ls -ld {} \;').stdout.split("\n")
  ww_dirs.each do |curr_dir|
    dir_arr = curr_dir.split(' ')
    # replace with be_in matcher
    describe.one do
      describe file(dir_arr.last) do
        its('group') { should cmp "root" }
      end
      describe file(dir_arr.last) do
        its('group') { should cmp "sys" }
      end
      describe file(dir_arr.last) do
        its('group') { should cmp "bin" }
      end
    end
  end
end
