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

# Should we verify the virus software installation?
check_virus_software = attribute(
                           'V_72213_Check_Virus_Software',
                           default: 1,
                           description: 'Check Virus Software is Installed and Running'
                         )

control "V-72213" do
  title "The system must use a DoD-approved virus scan program."
  desc  "
    Virus scanning software can be used to protect a system from penetration from
computer viruses and to limit their spread through intermediate systems.

    The virus scanning software should be configured to perform scans dynamically on
accessed files. If this capability is not available, the system must be configured
to scan, at a minimum, all altered files on the system on a daily basis.

    If the system processes inbound SMTP mail, the virus scanner must be configured
to scan all received mail.
  "
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72213"
  tag "rid": "SV-86837r1_rule"
  tag "stig_id": "RHEL-07-032000"
  tag "cci": "CCI-001668"
  tag "nist": ["SI-3 a", "Rev_3"]
  tag "check": "Verify the system is using a DoD-approved virus scan program.

Check for the presence of \"McAfee VirusScan Enterprise for Linux\" with the
following command:

# systemctl status nails
nails - service for McAfee VirusScan Enterprise for Linux
>  Loaded: loaded
/opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)
>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the \"nails\" service is not active, check for the presence of \"clamav\" on the
system with the following command:

# systemctl status clamav-daemon.socket
 systemctl status clamav-daemon.socket
  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)
     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If neither of these applications are loaded and active, ask the System Administrator
if there is an antivirus package installed and active on the system.

If no antivirus scan program is active on the system, this is a finding."
  tag "fix": "Install an approved DoD antivirus solution on the system."

  describe.one do
	describe service('nails') do
	  it { should be_running }
    end
	describe service('clamav-daemon.socket') do
	  it { should be_running }
	end
  end
  only_if { check_virus_software == 1 } 
end
