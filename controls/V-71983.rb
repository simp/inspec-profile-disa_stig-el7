# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

control "V-71983" do
  title "USB mass storage must be disabled."
  desc  "
    USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163,
SRG-OS-000480-GPOS-0022.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000114-GPOS-00059"
  tag "gid": "V-71983"
  tag "rid": "SV-86607r1_rule"
  tag "stig_id": "RHEL-07-020100"
  tag "nist": ["CM-6 b","IA-3","Rev_4"]
  tag "cci": ["CCI-000778","CCI-001958","CCI-000366"]
  tag "check": "If there is an HBSS with a Device Control Module and a Data Loss
Prevention mechanism, this requirement is not applicable.

Verify the operating system disables the ability to use USB mass storage devices.

Check to see if USB mass storage is disabled with the following command:

#grep -i usb-storage /etc/modprobe.d/*

install usb-storage /bin/true

If the command does not return any output, and use of USB storage devices is not
documented with the Information System Security Officer (ISSO) as an operational
requirement, this is a finding."
  tag "fix": "Configure the operating system to disable the ability to use USB mass
storage devices.

Create a file under \"/etc/modprobe.d\" with the following command:

#touch /etc/modprobe.d/nousbstorage

Add the following line to the created file:

install usb-storage /bin/true"

  # TODO ALWAYS check your resources
  describe kernel_module('usb-storage') do
    it { should be_blacklisted }
  end
end
