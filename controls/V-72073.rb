# encoding: utf-8
#
control "V-72073" do
  title "The file integrity tool must use FIPS 140-2 approved cryptographic
hashes for validating file contents and directories."
  desc  "File integrity tools use cryptographic hashes for verifying file
contents and directories have not been altered. These hashes must be FIPS 140-2
approved cryptographic hashes."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72073"
  tag "rid": "SV-86697r2_rule"
  tag "stig_id": "RHEL-07-021620"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['aide']
  desc "check", "Verify the file integrity tool is configured to use FIPS 140-2
approved cryptographic hashes for validating file contents and directories.

Note: If RHEL-07-021350 is a finding, this is automatically a finding as the
system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

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

Check the \"aide.conf\" file to determine if the \"sha512\" rule has been added
to the rule list being applied to the files and directories selection lists.

An example rule that includes the \"sha512\" rule follows:

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin
/sbin All          # apply the same custom rule to the files in sbin

If the \"sha512\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, or another file integrity tool is not using FIPS 140-2
approved cryptographic hashes for validating file contents and directories,
this is a finding."
  desc "fix", "Configure the file integrity tool to use FIPS 140-2 cryptographic
hashes for validating file and directory contents.

If AIDE is installed, ensure the \"sha512\" rule is present on all file and
directory selection lists."
  tag "fix_id": "F-78425r1_fix"

  # Redundant with V-72063
  describe package("aide") do
    it { should be_installed }
  end

  findings = []
  aide_conf.where { !selection_line.start_with? '!' }.entries.each do |selection|
    unless selection.rules.include? 'sha512'
      findings.append(selection.selection_line)
    end
  end

  describe "List of monitored files/directories without 'sha512' rule" do
    subject { findings }
    it { should be_empty }
  end
end
