# encoding: utf-8
#
control "V-72063" do
  title "The system must use a separate file system for the system audit data
path."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72063"
  tag "rid": "SV-86687r5_rule"
  tag "stig_id": "RHEL-07-021330"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['file_system']
  tag "fix_id": "F-78415r1_fix"
  desc "check", "Determine if the \"/var/log/audit\" path is a separate file
  system.

  # grep /var/log/audit /etc/fstab

  If no result is returned, \"/var/log/audit\" is not on a separate file system,
  and this is a finding."
  desc "fix", "Migrate the system audit data path onto a separate file system."

  describe mount('/var/log/audit') do
    it {should be_mounted}
  end

end
