# encoding: utf-8
#
control "V-71959" do
  title "The operating system must not allow a non-certificate trusted host SSH
logon to the system."
  desc  "Failure to restrict system access to authenticated users negatively
impacts operating system security."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71959"
  tag "rid": "SV-86583r2_rule"
  tag "stig_id": "RHEL-07-010470"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the operating system does not allow a non-certificate
trusted host SSH logon to the system.

Check for the value of the \"HostbasedAuthentication\" keyword with the
following command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the \"HostbasedAuthentication\" keyword is not set to \"no\", is missing, or
is commented out, this is a finding."
  tag "fix": "Configure the operating system to not allow a non-certificate
trusted host SSH logon to the system.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for
\"HostbasedAuthentication\" keyword and set the value to \"no\":

HostbasedAuthentication no

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78311r3_fix"
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end
