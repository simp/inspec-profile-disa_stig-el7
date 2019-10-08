# encoding: utf-8
#
control "V-72061" do
  title "The system must use a separate file system for /var."
  desc  "The use of separate file systems for different paths can protect the
  system from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72061"
  tag "rid": "SV-86685r1_rule"
  tag "stig_id": "RHEL-07-021320"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "fix_id": "F-78413r1_fix"
  tag "subsystems": ['/var', 'file_system']
  tag "nist": ["CM-6 b", "Rev_4"]
  desc "check", "Verify that a separate file system/partition has been created
  for \"/var\".

  Check that a file system/partition has been created for \"/var\" with the
  following command:

  # grep /var /etc/fstab
  
  UUID=c274f65f /var ext4 noatime,nobarrier 1 2

  If a separate entry for \"/var\" is not in use, this is a finding."
  
  desc "fix", "Migrate the \"/var\" path onto a separate file system."

  describe mount('/var') do
    it { should be_mounted }
  end
end
