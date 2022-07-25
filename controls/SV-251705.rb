control 'SV-251705' do
  title 'The Red Hat Enterprise Linux operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc  "Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.\n\nThis requirement applies to the Red Hat Enterprise Linux operating system performing security function verification/testing and/or systems and environments that require this functionality."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag satisfies: nil
  tag gid: 'V-251705'
  tag rid: 'SV-251705r809229_rule'
  tag stig_id: 'RHEL-07-020029'
  tag fix_id: 'F-55096r809228_fix'
  tag cci: ['CCI-002696']
  tag legacy: []
  tag subsystems: ["file_integrity_tool"]
  tag 'host', 'container'
  tag check: "Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.\n\nCheck that the AIDE package is installed with the following command:\n\n$ sudo rpm -q aide\n\naide-0.16-14.el8.x86_64\n\nIf AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. \n\nIf there is no application installed to perform integrity checks, this is a finding."
  tag fix: "Install the AIDE package by running the following command:\n\n$ sudo yum install aide"

  describe package(input('file_integrity_tool')) do
    it { should be_installed }
  end
end
