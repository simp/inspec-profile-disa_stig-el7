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

control "V-72251" do
  title "The SSH daemon must be configured to only use the SSHv2 protocol."
  desc  "
    SSHv1 is an insecure implementation of the SSH protocol and has many well-known
vulnerability exploits. Exploits of the SSH daemon could provide immediate root
access to the system."

  impact 0.7

  tag "gtitle": "SRG-OS-000074-GPOS-00042"
  tag "gid": "V-72251"
  tag "rid": "SV-86875r2_rule"
  tag "stig_id": "RHEL-07-040390"
  tag "cci": ["CCI-000197","CCI-000366"]
  tag "nist": ["IA-5 (1) (c)","CM-6 b","Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH daemon is configured to only use the SSHv2 protocol.

Check that the SSH daemon is configured to only use the SSHv2 protocol with the
following command:

# grep -i protocol /etc/ssh/sshd_config
Protocol 2
#Protocol 1,2

If any protocol line other than \"Protocol 2\" is uncommented, this is a finding."
  tag "fix": "Remove all Protocol lines that reference version \"1\" in
\"/etc/ssh/sshd_config\" (this file may be named differently or be in a different
location if using a version of SSH that is provided by a third-party vendor). The
\"Protocol\" line must be as follows:

Protocol 2

The SSH service must be restarted for changes to take effect."

  describe sshd_config do
    its('Protocol') { should cmp '2' }
  end
end
