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

control "V-71985" do
  title "File system automounter must be disabled unless required."
  desc  "
    Automatically mounting file systems permits easy introduction of unknown
devices, thereby facilitating malicious activity.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163,
SRG-OS-000480-GPOS-0022.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000114-GPOS-00059"
  tag "gid": "V-71985"
  tag "rid": "SV-86609r1_rule"
  tag "stig_id": "RHEL-07-020110"
  tag "nist": ["CM-6 b","IA-3","Rev_4"]
  tag "cci": ["CCI-000778","CCI-000366","CCI-001958"]
  tag "check": "Verify the operating system disables the ability to automount
devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
autofs.service - Automounts filesystems on demand
   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
   Active: inactive (dead)

If the \"autofs\" status is set to \"active\" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this is a
finding."
  tag "fix": "Configure the operating system to disable the ability to automount
devices.

Turn off the automount service with the following command:

# systemctl disable autofs

If \"autofs\" is required for Network File System (NFS), it must be documented with
the ISSO."

  describe systemd_service('autofs.service') do
    it { should_not be_running }
    it { should_not be_enabled }
    it { should_not be_installed }
  end
end
