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

control "V-72009" do
  title "All files and directories must have a valid group owner."
  desc  "Files without a valid group owner may be unintentionally inherited if a
group is assigned the same Group Identifier (GID) as the GID of the files without a
valid group owner."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72009"
  tag "rid": "SV-86633r1_rule"
  tag "stig_id": "RHEL-07-020330"
  tag "cci": "CCI-002165"
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "check": "Verify all files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used
as an example.

# find / -xdev -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding."
  tag "fix": "Either remove all files and directories from the system that do not
have a valid group, or assign a valid group to all files and directories on the
system with the \"chgrp\" command:

# chgrp <group> <file>"

  describe command('find / -xdev -fstype xfs -nogroup') do
    its('stdout.strip') { should match /^$/ }
  end
end
