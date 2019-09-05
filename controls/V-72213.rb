# encoding: utf-8
#
control "V-72213" do
  title "The system must use a virus scan program."
  desc  "
    Virus scanning software can be used to protect a system from penetration
from computer viruses and to limit their spread through intermediate systems.

    The virus scanning software should be configured to perform scans
dynamically on accessed files. If this capability is not available, the system
must be configured to scan, at a minimum, all altered files on the system on a
daily basis.

    If the system processes inbound SMTP mail, the virus scanner must be
configured to scan all received mail.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72213"
  tag "rid": "SV-86837r2_rule"
  tag "stig_id": "RHEL-07-032000"
  tag "cci": ["CCI-001668"]
  tag "documentable": false
  tag "nist": ["SI-3 a", "Rev_4"]
  tag "subsystems": ['clamav', 'nails', 'virus_scan']
  tag "check": "Verify the system is using a virus scan program.

Check for the presence of \"McAfee VirusScan Enterprise for Linux\" with the
following command:

# systemctl status nails
nails - service for McAfee VirusScan Enterprise for Linux
>  Loaded: loaded
/opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>;
enabled)
>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the \"nails\" service is not active, check for the presence of \"clamav\" on
the system with the following command:

# systemctl status clamav-daemon.socket
 systemctl status clamav-daemon.socket
  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)
     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If neither of these applications are loaded and active, ask the System
Administrator if there is an antivirus package installed and active on the
system.

If no antivirus scan program is active on the system, this is a finding."
  tag "fix": "Install an antivirus solution on the system."
  tag "fix_id": "F-78567r2_fix"

  describe.one do
	  describe service('nails') do
	    it { should be_running }
    end
    describe service('clamav-daemon.socket') do
	    it { should be_running }
	  end
  end
end
