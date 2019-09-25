# encoding: utf-8
#
control "V-72267" do
  title "The SSH daemon must not allow compression or must only allow
compression after successful authentication."
  desc  "If compression is allowed in an SSH connection prior to
authentication, vulnerabilities in the compression software could result in
compromise of the system from an unauthenticated connection, potentially with
root privileges."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72267"
  tag "rid": "SV-86891r2_rule"
  tag "stig_id": "RHEL-07-040470"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH daemon performs compression after a user
successfully authenticates.

Check that the SSH daemon performs compression after a user successfully
authenticates with the following command:

# grep -i compression /etc/ssh/sshd_config
Compression delayed

If the \"Compression\" keyword is set to \"yes\", is missing, or the retuned
line is commented out, this is a finding."
  tag "fix": "Uncomment the \"Compression\" keyword in \"/etc/ssh/sshd_config\"
(this file may be named differently or be in a different location if using a
version of SSH that is provided by a third-party vendor) on the system and set
the value to \"delayed\" or \"no\":

Compression no

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78621r2_fix"

  describe.one do
    describe sshd_config do
      its('Compression') { should cmp 'delayed' }
    end
    describe sshd_config do
      its('Compression') { should cmp 'no' }
    end
  end
end
