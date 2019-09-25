# encoding: utf-8
#
control "V-71989" do
  title "The operating system must enable SELinux."
  desc  "
    Without verification of the security functions, security functions may not
operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this
functionality.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000445-GPOS-00199"
  tag "gid": "V-71989"
  tag "rid": "SV-86613r2_rule"
  tag "stig_id": "RHEL-07-020210"
  tag "cci": ["CCI-002165", "CCI-002696"]
  tag "documentable": false
  tag "nist": ["AC-3 (4)", "SI-6 a", "Rev_4"]
  tag "subsystems": ['selinux']
  desc "check", "Verify the operating system verifies correct operation of all
security functions.

Check if \"SELinux\" is active and in \"Enforcing\" mode with the following
command:

# getenforce
Enforcing

If \"SELinux\" is not active and not in \"Enforcing\" mode, this is a finding."
  desc "fix", "Configure the operating system to verify correct operation of all
security functions.

Set the \"SELinux\" status and the \"Enforcing\" mode by modifying the
\"/etc/selinux/config\" file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect."
  tag "fix_id": "F-78341r2_fix"

  # TODO SELinux resource?? (https://github.com/chef/inspec/issues/534)
  describe command('getenforce') do
    its('stdout.strip') { should eq 'Enforcing' }
  end
end
