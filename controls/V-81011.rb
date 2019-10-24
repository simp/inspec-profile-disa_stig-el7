# encoding: utf-8
#
control "V-81011" do
  title "The Red Hat Enterprise Linux operating system must mount /dev/shm with the nosuid option."
  desc  "
  The \"nosuid\" mount option causes the system to not execute \"setuid\" and \setgid\" files with owner privileges. 
  This option must be used for mounting any file system not containing approved \"setuid\" and \"setguid\" files. 
  Executing files from untrusted file systems increases the opportunity for unprivileged users to attain 
  unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000368-GPOS-00154"
  tag "gid": "V-81011"
  tag "rid": "SV-95723r1_rule"
  tag "stig_id": "RHEL-07-021023"
  tag "cci": ["CCI-001764"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['file_system']
  desc "check", "
  The \"nosuid\" mount option causes the system to not execute \"setuid\" and \"setgid\" files with owner privileges. 
  This option must be used for mounting any file system not containing approved \"setuid\" and \"setguid\" files. 
  Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
  "
  desc "fix", "
  Configure the system so that /dev/shm is mounted with the \"nosuid\" option.
  "

  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end
