# encoding: utf-8
#
control "V-72007" do
  title "All files and directories must have a valid owner."
  desc  "Unowned files and directories may be unintentionally inherited if a
user is assigned the same User Identifier \"UID\" as the UID of the un-owned
files."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72007"
  tag "rid": "SV-86631r2_rule"
  tag "stig_id": "RHEL-07-020320"
  tag "cci": ["CCI-002165"]
  tag "documentable": false
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "subsystems": ['file_system', 'users' ,'files']
  desc "check", "Verify all files and directories on the system have a valid
owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is
used as an example.

# find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding."
  desc "fix", "Either remove all files and directories from the system that do
not have a valid user, or assign a valid user to all unowned files and
directories on the system with the \"chown\" command:

# chown <user> <file>"
  tag "fix_id": "F-78359r1_fix"

  command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'').
    stdout.strip.split("\n").each do |fs|
      describe command("find / -xautofs -fstype #{fs} -nouser") do
        its('stdout.strip') { should be_empty }
      end
    end
end
