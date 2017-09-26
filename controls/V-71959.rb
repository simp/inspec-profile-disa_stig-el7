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

control "V-71959" do
  title "The operating system must not allow a non-certificate trusted host SSH
logon to the system."
  desc  "Failure to restrict system access to authenticated users negatively impacts
operating system security."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71959"
  tag "rid": "SV-86583r2_rule"
  tag "stig_id": "RHEL-07-010470"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the operating system does not allow a non-certificate trusted
host SSH logon to the system.

Check for the value of the \"HostbasedAuthentication\" keyword with the following
command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the \"HostbasedAuthentication\" keyword is not set to \"no\", is missing, or is
commented out, this is a finding."
  tag "fix": "Configure the operating system to not allow a non-certificate trusted
host SSH logon to the system.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for
\"HostbasedAuthentication\" keyword and set the value to \"no\":

HostbasedAuthentication no

The SSH service must be restarted for changes to take effect."

  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end
