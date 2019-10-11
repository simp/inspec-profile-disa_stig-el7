# encoding: utf-8
#
control "V-81009" do
  title "The Red Hat Enterprise Linux operating system must mount /dev/shm with the nodev option."
  desc  "
  The \"nodev\" mount option causes the system to not interpret character or block special devices. 
  Executing character or block special devices from untrusted file systems increases the opportunity 
  for unprivileged users to attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000368-GPOS-00154"
  tag "gid": "V-81009"
  tag "rid": "SV-95721r1_rule "
  tag "stig_id": "RHEL-07-021022"
  tag "cci": ["CCI-001764"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['file_system']
  desc "check", "
  Verify that the \"nodev\" option is configured for /dev/shm.

  Check that the operating system is configured to use the \"nodev\" option for /dev/shm with the following command:

  # cat /etc/fstab | grep /dev/shm | grep nodev

  tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

  If the \"nodev\" option is not present on the line for \"/dev/shm\", this is a finding.

  Verify \"/dev/shm\" is mounted with the \"nodev\" option:

  # mount | grep \"/dev/shm\" | grep nodev

  If no results are returned, this is a finding.
  "
  desc "fix", "
  Configure the \"/etc/fstab\" to use the \"nodev\" option for all lines containing \"/dev/shm\".
  "

  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end
