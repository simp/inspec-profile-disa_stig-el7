# encoding: utf-8
#
control "V-72269" do
  title "The operating system must, for networked systems, synchronize clocks
with a server that is synchronized to one of the redundant United States Naval
Observatory (USNO) time servers, a time server designated for the appropriate
DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can
lead to an inaccurate analysis. Determining the correct time a particular event
occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000355-GPOS-00143"
  tag "satisfies": ["SRG-OS-000355-GPOS-00143", "SRG-OS-000356-GPOS-00144"]
  tag "gid": "V-72269"
  tag "rid": "SV-86893r2_rule"
  tag "stig_id": "RHEL-07-040500"
  tag "cci": ["CCI-001891", "CCI-002046"]
  tag "documentable": false
  tag "nist": ["AU-8 (1) (a)", "AU-8 (1) (b)", "Rev_4"]
  tag "check": "Check to see if NTP is running in continuous mode.

# ps -ef | grep ntp

If NTP is not running, this is a finding.

If the process is found, then check the \"ntp.conf\" file for the \"maxpoll\"
option setting:

# grep maxpoll /etc/ntp.conf

maxpoll 17

If the option is set to \"17\" or is not set, this is a finding.

If the file does not exist, check the \"/etc/cron.daily\" subdirectory for a
crontab file controlling the execution of the \"ntpdate\" command.

# grep –l ntpdate /etc/cron.daily

# ls -al /etc/cron.* | grep ntp
ntp

If a crontab file does not exist in the \"/etc/cron.daily\" that executes the
\"ntpdate\" file, this is a finding."
  tag "fix": "Edit the \"/etc/ntp.conf\" file and add or update an entry to
define \"maxpoll\" to \"10\" as follows:

maxpoll 10

If NTP was running and \"maxpoll\" was updated, the NTP service must be
restarted:

# systemctl restart ntpd

If NTP was not running, it must be started:

# systemctl start ntpd"
  tag "fix_id": "F-78623r3_fix"

  describe service('ntpd') do
    it { should be_running }
  end
  describe.one do
    describe command('grep maxpoll /etc/ntp.conf') do
      its('stdout.strip') { should match %r{^\s*maxpoll\s+[1-9][0-9]*$} }
      its('stdout.strip') { should_not match %r{^\s*maxpoll\s+17$} }
    end
    # Case where maxpoll empty
    describe file('/etc/cron.daily/ntpdate') do
      it { should exist }
    end
  end
end
