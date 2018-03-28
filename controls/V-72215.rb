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
                           'V_72215_Check_Virus_Software',
                           default: 1,
                           description: 'Check Virus Software is Installed, Running, and up-to-date'
                         )

control "V-72215" do
  title "The system must update the DoD-approved virus scan program every seven days
or more frequently."
  desc  "
    Virus scanning software can be used to protect a system from penetration from
computer viruses and to limit their spread through intermediate systems.

    The virus scanning software should be configured to check for software and virus
definition updates with a frequency no longer than seven days. If a manual process
is required to update the virus scan software or definitions, it must be documented
with the Information System Security Officer (ISSO).
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72215"
  tag "rid": "SV-86839r1_rule"
  tag "stig_id": "RHEL-07-032010"
  tag "cci": "CCI-001668"
  tag "nist": ["SI-3 a", "Rev_3"]
  tag "check": "Verify the system is using a DoD-approved virus scan program and the
virus definition file is less than seven days old.

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

If \"McAfee VirusScan Enterprise for Linux\" is active on the system, check the
dates of the virus definition files with the following command:

# ls -al /opt/NAI/LinuxShield/engine/dat/*.dat
<need output>

If the virus definition files have dates older than seven days from the current
date, this is a finding.

If \"clamav\" is active on the system, check the dates of the virus database with
the following commands:

# grep -I databasedirectory /etc/clamav.conf
DatabaseDirectory /var/lib/clamav

# ls -al /var/lib/clamav/*.cvd
-rwxr-xr-x  1 root root      149156 Mar  5  2011 daily.cvd

If the database file has a date older than seven days from the current date, this is
a finding."
  tag "fix": "Update the approved DoD virus scan software and virus definition
files."

  sec_per_wk = 604800
  describe.one do
	describe systemd_service('nails') do
	  it { should be_running }
	end
	describe systemd_service('clamav-daemon.socket') do
	  it { should be_running }
	end
  end
  if systemd_service('nails').running?
	virus_defs = Dir["/opt/NAI/LinuxShield/engine/dat/*.dat"]
	virus_defs.each do |curr_def|
	  describe file(curr_def).mtime.to_i do
		it { should >= Time.now.to_i - sec_per_wk }
	  end
    end
  end
  if systemd_service('clamav-daemon.socket').running?
	cvd_files = Dir["/var/lib/clamav/*.cvd"]
	cvd_files.each do |curr_file|
	  describe file(curr_file).mtime.to_i do
		it { should >= Time.now.to_i - sec_per_wk }
	  end
	end
  end
  only_if { check_virus_software == 1 } 
  
end
