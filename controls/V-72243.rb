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

control "V-72243" do
  title "The SSH daemon must not allow authentication using rhosts authentication."
  desc  "Configuring this setting for the SSH daemon provides additional assurance
that remote logon via SSH will require a password, even in the event of
misconfiguration elsewhere."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72243"
  tag "rid": "SV-86867r2_rule"
  tag "stig_id": "RHEL-07-040350"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the SSH daemon does not allow authentication using known
hosts authentication.

To determine how the SSH daemon's \"IgnoreRhosts\" option is set, run the following
command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

IgnoreRhosts yes

If the value is returned as \"no\", the returned line is commented out, or no output
is returned, this is a finding."
  tag "fix": "Configure the SSH daemon to not allow authentication using known hosts
authentication.

Add the following line in \"/etc/ssh/sshd_config\", or uncomment the line and set
the value to \"yes\":

IgnoreRhosts yes"

  describe sshd_config do
    its('IgnoreRhosts') { should cmp 'yes' }
  end
end
