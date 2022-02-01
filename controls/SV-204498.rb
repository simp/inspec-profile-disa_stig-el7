control 'SV-204498' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is
    configured to verify Access Control Lists (ACLs).'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file
    integrity tools.'
  tag 'legacy': ['SV-86693', 'V-72069']
  tag 'rationale': ''
  tag 'check': 'Verify the file integrity tool is configured to verify ACLs.
    Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following
    command:
    # yum list installed aide
    If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.
    If there is no application installed to perform file integrity checks, this is a finding.
    Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc"
    directory.
    Use the following command to determine if the file is in another location:
    # find / -name aide.conf
    Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files
    and directories selection lists.
    An example rule that includes the "acl" rule is below:
    All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
    /bin All # apply the custom rule to the files in bin
    /sbin All # apply the same custom rule to the files in sbin
    If the "acl" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or ACLs are not
    being checked by another file integrity tool, this is a finding.'
  tag 'fix': 'Configure the file integrity tool to check file and directory ACLs.
    If AIDE is installed, ensure the "acl" rule is present on all uncommented file and directory selection lists.'
  impact 0.3
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204498'
  tag 'rid': 'SV-204498r603261_rule'
  tag 'stig_id': 'RHEL-07-021600'
  tag 'fix_id': 'F-4622r88687_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('aide') do
    it { should be_installed }
  end

  findings = []
  aide_conf.where { !selection_line.start_with? '!' }.entries.each do |selection|
    findings.append(selection.selection_line) unless selection.rules.include? 'acl'
  end

  describe "List of monitored files/directories without 'acl' rule" do
    subject { findings }
    it { should be_empty }
  end
end
