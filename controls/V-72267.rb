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

control "V-72267" do
  title "The SSH daemon must not allow compression or must only allow compression
after successful authentication."
  desc  "If compression is allowed in an SSH connection prior to authentication,
vulnerabilities in the compression software could result in compromise of the system
from an unauthenticated connection, potentially with root privileges."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72267"
  tag "rid": "SV-86891r2_rule"
  tag "stig_id": "RHEL-07-040470"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH daemon performs compression after a user successfully
authenticates.

Check that the SSH daemon performs compression after a user successfully
authenticates with the following command:

# grep -i compression /etc/ssh/sshd_config
Compression delayed

If the \"Compression\" keyword is set to \"yes\", is missing, or the retuned line is
commented out, this is a finding."
  tag "fix": "Uncomment the \"Compression\" keyword in \"/etc/ssh/sshd_config\"
(this file may be named differently or be in a different location if using a version
of SSH that is provided by a third-party vendor) on the system and set the value to
\"delayed\" or \"no\":

Compression no

The SSH service must be restarted for changes to take effect."

  describe.one do
    describe sshd_config do
      its('Compression') { should cmp 'delayed' }
    end
    describe sshd_config do
      its('Compression') { should cmp 'no' }
    end
  end
end
