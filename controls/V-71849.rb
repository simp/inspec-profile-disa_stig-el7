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

control "V-71849" do
  title "The file permissions, ownership, and group membership of system files and
commands must match the vendor values."
  desc  "
    Discretionary access control is weakened if a user or group has access
permissions to system files and directories greater than the default.

    Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-0010.
  "
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000257-GPOS-00098"
  tag "gid": "V-71849"
  tag "rid": "SV-86473r2_rule"
  tag "stig_id": "RHEL-07-010010"
  tag "cci": "CCI-001494"
  tag "nist": ["AU-9", "Rev_4"]
  tag "cci": "CCI-001496"
  tag "nist": ["AU-9 (3)", "Rev_4"]
  tag "check": "Verify the file permissions, ownership, and group membership of
system files and commands match the vendor values.

Check the file permissions, ownership, and group membership of system files and
commands with the following command:

# rpm -Va | grep '^.M'

If there is any output from the command indicating that the ownership or group of a
system file or command, or a system file, has permissions less restrictive than the
default, this is a finding."

  tag "fix": "Run the following command to determine which package owns the file:

# rpm -qf <filename>

Reset the permissions of files within a package with the following command:

#rpm --setperms <packagename>

Reset the user and group ownership of files within a package with the following
command:

#rpm --setugids <packagename>"

  # @todo add puppet content to fix any rpms that get out of wack
  describe command("rpm -Va | grep '^.M' | wc -l") do
    its('stdout.strip') { should eq '0' }
  end

end
