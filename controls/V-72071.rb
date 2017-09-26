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

control "V-72071" do
  title "The file integrity tool must be configured to verify extended attributes."
  desc  "Extended attributes in file systems are used to contain arbitrary data and
file metadata with security implications."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72071"
  tag "rid": "SV-86695r2_rule"
  tag "stig_id": "RHEL-07-021610"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the file integrity tool is configured to verify extended
attributes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the
system with the following command:

# yum list installed aide

If AIDE is not installed, ask the System Administrator how file integrity checks are
performed on the system.

If there is no application installed to perform file integrity checks, this is a
finding.

Note: AIDE is highly configurable at install time. These commands assume the
\"aide.conf\" file is under the \"/etc\" directory.

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the \"aide.conf\" file to determine if the \"xattrs\" rule has been added to
the rule list being applied to the files and directories selection lists.

An example rule that includes the \"xattrs\" rule follows:

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin
/sbin All          # apply the same custom rule to the files in sbin

If the \"xattrs\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, or extended attributes are not being checked by another
file integrity tool, this is a finding."
  tag "fix": "Configure the file integrity tool to check file and directory extended
attributes.

If AIDE is installed, ensure the \"xattrs\" rule is present on all file and
directory selection lists."

  describe package("aide") do
    it { should be_installed }
  end
  describe aide_conf.all_have_rule('xattrs') do
    it { should eq true }
  end
end
