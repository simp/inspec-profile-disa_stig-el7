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

control "V-72263" do
  title "The SSH daemon must perform strict mode checking of home directory
configuration files."
  desc  "If other users have access to modify user-specific SSH configuration files,
they may be able to log on to the system as another user."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72263"
  tag "rid": "SV-86887r2_rule"
  tag "stig_id": "RHEL-07-040450"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the SSH daemon performs strict mode checking of home
directory configuration files.

The location of the \"sshd_config\" file may vary if a different daemon is in use.

Inspect the \"sshd_config\" file with the following command:

# grep -i strictmodes /etc/ssh/sshd_config

StrictModes yes

If \"StrictModes\" is set to \"no\", is missing, or the returned line is commented
out, this is a finding."
  tag "fix": "Uncomment the \"StrictModes\" keyword in \"/etc/ssh/sshd_config\"
(this file may be named differently or be in a different location if using a version
of SSH that is provided by a third-party vendor) and set the value to \"yes\":

StrictModes yes

The SSH service must be restarted for changes to take effect."

  describe sshd_config do
    its('StrictModes') { should cmp 'yes' }
  end
end
