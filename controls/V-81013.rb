# encoding: utf-8
#
control "V-81013" do
  title "The Red Hat Enterprise Linux operating system must mount /dev/shm with the noexec option."
  desc  "The \"noexec\" mount option causes the system to not execute binary files. This option 
  must be used for mounting any file system not containing approved binary files as they may be 
  incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged 
  users to attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000368-GPOS-00154"
  tag "gid": "V-81013"
  tag "rid": "SV-95725r1_rule"
  tag "stig_id": "RHEL-07-001764"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['file_system']
  desc "check", "
  The \"noexec\" mount option causes the system to not execute binary files. This option must be used 
  for mounting any file system not containing approved binary files as they may be incompatible. Executing 
  files from untrusted file systems increases the opportunity for unprivileged users to attain 
  unauthorized administrative access.
  "
  desc "fix", "
  Configure the system so that /dev/shm is mounted with the \"noexec\" option.
  "

  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end
end
