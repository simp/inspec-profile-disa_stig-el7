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

control "V-72007" do
  title "All files and directories must have a valid owner."
  desc  "Unowned files and directories may be unintentionally inherited if a user is
assigned the same User Identifier \"UID\" as the UID of the un-owned files."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72007"
  tag "rid": "SV-86631r1_rule"
  tag "stig_id": "RHEL-07-020320"
  tag "cci": "CCI-002165"
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "check": "Verify all files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used
as an example.

# find / -xdev -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding."
  tag "fix": "Either remove all files and directories from the system that do not
have a valid user, or assign a valid user to all unowned files and directories on
the system with the \"chown\" command:

# chown <user> <file>"

  describe command('find / -xdev -fstype xfs -nouser') do
    its('stdout.strip') { should match /^$/ }
  end
end
