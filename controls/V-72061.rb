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

control "V-72061" do
  title "The system must use a separate file system for /var."
  desc  "The use of separate file systems for different paths can protect the system
from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72061"
  tag "rid": "SV-86685r1_rule"
  tag "stig_id": "RHEL-07-021320"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that a separate file system/partition has been created for
\"/var\".

Check that a file system/partition has been created for \"/var\" with the following
command:

# grep /var /etc/fstab
UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2

If a separate entry for \"/var\" is not in use, this is a finding."
  tag "fix": "Migrate the \"/var\" path onto a separate file system."

  # note: the directory resource is a symlink to the 'file' resource
  describe directory('/var') do
    it { should be_mounted }
  end
end
