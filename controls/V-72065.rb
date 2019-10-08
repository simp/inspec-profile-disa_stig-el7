# encoding: utf-8
#
control "V-72065" do
  title "The system must use a separate file system for /tmp (or equivalent)."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.3
  
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72065"
  tag "rid": "SV-86689r1_rule"
  tag "stig_id": "RHEL-07-021340"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['file_system', 'tmp']
  tag "fix_id": "F-78417r1_fix"
  
  desc "check", "Verify that a separate file system/partition has been created
  for \"/tmp\".

  Check that a file system/partition has been created for \"/tmp\" with the
  following command:

  # systemctl is-enabled tmp.mount
  enabled

  If the \"tmp.mount\" service is not enabled, this is a finding."

  desc "fix", "Start the \"tmp.mount\" service with the following command:
  
  # systemctl enable tmp.mount"

  describe systemd_service('tmp.mount') do
    it { should be_enabled }
  end
end
