# encoding: utf-8
#
control "V-72251" do
  title "The SSH daemon must be configured to only use the SSHv2 protocol."
  desc  "SSHv1 is an insecure implementation of the SSH protocol and has many
well-known vulnerability exploits. Exploits of the SSH daemon could provide
immediate root access to the system."
  impact 0.7
  tag "gtitle": "SRG-OS-000074-GPOS-00042"
  tag "satisfies": ["SRG-OS-000074-GPOS-00042", "SRG-OS-000480-GPOS-00227"]
  tag "gid": "V-72251"
  tag "rid": "SV-86875r3_rule"
  tag "stig_id": "RHEL-07-040390"
  tag "cci": ["CCI-000197", "CCI-000366"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (c)", "CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Check the version of the operating system with the following
command:

# cat /etc/redhat-release

If the release is 7.4 or newer this requirement is Not Applicable.

Verify the SSH daemon is configured to only use the SSHv2 protocol.

Check that the SSH daemon is configured to only use the SSHv2 protocol with the
following command:

# grep -i protocol /etc/ssh/sshd_config
Protocol 2
#Protocol 1,2

If any protocol line other than \"Protocol 2\" is uncommented, this is a
finding."
  tag "fix": "Remove all Protocol lines that reference version \"1\" in
\"/etc/ssh/sshd_config\" (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party
vendor). The \"Protocol\" line must be as follows:

Protocol 2

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78605r2_fix"

  describe sshd_config do
    its('Protocol') { should cmp '2' }
  end
end
