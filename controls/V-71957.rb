# encoding: utf-8
#
control "V-71957" do
  title "The operating system must not allow users to override SSH environment
variables."
  desc  "Failure to restrict system access to authenticated users negatively
impacts operating system security."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71957"
  tag "rid": "SV-86581r2_rule"
  tag "stig_id": "RHEL-07-010460"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  desc "check", "Verify the operating system does not allow users to override
environment variables to the SSH daemon.

Check for the value of the \"PermitUserEnvironment\" keyword with the following
command:

# grep -i permituserenvironment /etc/ssh/sshd_config
PermitUserEnvironment no

If the \"PermitUserEnvironment\" keyword is not set to \"no\", is missing, or
is commented out, this is a finding."
  desc "fix", "Configure the operating system to not allow users to override
environment variables to the SSH daemon.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for
\"PermitUserEnvironment\" keyword and set the value to \"no\":

PermitUserEnvironment no

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78309r2_fix"
  # the `i` will ignore case
  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end
