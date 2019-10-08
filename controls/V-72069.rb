# encoding: utf-8
#
control "V-72069" do
  title "The file integrity tool must be configured to verify Access Control
Lists (ACLs)."
  desc  "ACLs can provide permissions beyond those permitted through the file
mode and must be verified by file integrity tools."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72069"
  tag "rid": "SV-86693r2_rule"
  tag "stig_id": "RHEL-07-021600"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['aide']
  desc "check", "Verify the file integrity tool is configured to verify ACLs.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on
the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

If there is no application installed to perform file integrity checks, this is
a finding.

Note: AIDE is highly configurable at install time. These commands assume the
\"aide.conf\" file is under the \"/etc\" directory.

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the \"aide.conf\" file to determine if the \"acl\" rule has been added to
the rule list being applied to the files and directories selection lists.

An example rule that includes the \"acl\" rule is below:

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin
/sbin All          # apply the same custom rule to the files in sbin

If the \"acl\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, or ACLs are not being checked by another file
integrity tool, this is a finding."
  desc "fix", "Configure the file integrity tool to check file and directory
ACLs.

If AIDE is installed, ensure the \"acl\" rule is present on all file and
directory selection lists."
  tag "fix_id": "F-78421r1_fix"

  describe package("aide") do
    it { should be_installed }
  end

  findings = []
  aide_conf.where { !selection_line.start_with? '!' }.entries.each do |selection|
    unless selection.rules.include? 'acl'
      findings.append(selection.selection_line)
    end
  end

  describe "List of monitored files/directories without 'acl' rule" do
    subject { findings }
    it { should be_empty }
  end
end
