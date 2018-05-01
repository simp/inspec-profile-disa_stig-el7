# encoding: utf-8
#
control "V-71983" do
  title "USB mass storage must be disabled."
  desc  "USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity."
  impact 0.5
  tag "gtitle": "SRG-OS-000114-GPOS-00059"
  tag "satisfies": ["SRG-OS-000114-GPOS-00059", "SRG-OS-000378-GPOS-00163",
"SRG-OS-000480-GPOS-00227"]
  tag "gid": "V-71983"
  tag "rid": "SV-86607r2_rule"
  tag "stig_id": "RHEL-07-020100"
  tag "cci": ["CCI-000366", "CCI-000778", "CCI-001958"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "IA-3", "IA-3", "Rev_4"]
  tag "check": "If there is an HBSS with a Device Control Module and a Data
Loss Prevention mechanism, this requirement is not applicable.

Verify the operating system disables the ability to use USB mass storage
devices.

Check to see if USB mass storage is disabled with the following command:

# grep usb-storage /etc/modprobe.d/blacklist.conf
blacklist usb-storage

If the command does not return any output or the output is not \"blacklist
usb-storage\", and use of USB storage devices is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding."
  tag "fix": "Configure the operating system to disable the ability to use USB
mass storage devices.

# vi /etc/modprobe.d/blacklist.conf

Add or update the line:

blacklist usb-storage"
  tag "fix_id": "F-78335r2_fix"

  # TODO ALWAYS check your resources
  describe kernel_module('usb_storage') do
    it { should be_blacklisted }
  end
end

