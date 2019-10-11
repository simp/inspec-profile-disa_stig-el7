# encoding: utf-8
#
control "V-71985" do
  title "File system automounter must be disabled unless required."
  desc  "Automatically mounting file systems permits easy introduction of
unknown devices, thereby facilitating malicious activity."
  impact 0.5
  tag "gtitle": "SRG-OS-000114-GPOS-00059"
  tag "satisfies": ["SRG-OS-000114-GPOS-00059", "SRG-OS-000378-GPOS-00163",
"SRG-OS-000480-GPOS-00227"]
  tag "gid": "V-71985"
  tag "rid": "SV-86609r1_rule"
  tag "stig_id": "RHEL-07-020110"
  tag "cci": ["CCI-000366", "CCI-000778", "CCI-001958"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "IA-3", "IA-3", "Rev_4"]
  tag "subsystems": ['file_system', 'nfs', 'autofs']
  desc "check", "Verify the operating system disables the ability to automount
devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
autofs.service - Automounts filesystems on demand
   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
   Active: inactive (dead)

If the \"autofs\" status is set to \"active\" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding."
  desc "fix", "Configure the operating system to disable the ability to
automount devices.

Turn off the automount service with the following command:

# systemctl disable autofs

If \"autofs\" is required for Network File System (NFS), it must be documented
with the ISSO."
  tag "fix_id": "F-78337r1_fix"

  describe systemd_service('autofs.service') do
    it { should_not be_running }
    it { should_not be_enabled }
    it { should_not be_installed }
  end
end
