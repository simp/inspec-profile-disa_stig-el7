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

log_pkg_path = attribute(
  'log_pkg_path',
  default: '/etc/rsyslog.conf',
  description: "The path to the logging package"
)

control "V-72051" do
  title "Cron logging must be implemented."
  desc  "Cron logging can be used to trace the successful or unsuccessful execution
of cron jobs. It can also be used to spot intrusions into the use of the cron
facility by unauthorized and malicious users."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72051"
  tag "rid": "SV-86675r1_rule"
  tag "stig_id": "RHEL-07-021100"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that \"rsyslog\" is configured to log cron events.

Check the configuration of \"/etc/rsyslog.conf\" for the cron facility with the
following command:

Note: If another logging package is used, substitute the utility configuration file
for \"/etc/rsyslog.conf\".

# grep cron /etc/rsyslog.conf
cron.* /var/log/cron.log

If the command does not return a response, check for cron logging all facilities by
inspecting the \"/etc/rsyslog.conf\" file:

# more /etc/rsyslog.conf

Look for the following entry:

*.* /var/log/messages

If \"rsyslog\" is not logging messages for the cron facility or all facilities, this
is a finding.

If the entry is in the \"/etc/rsyslog.conf\" file but is after the entry \"*.*\",
this is a finding."
  tag "fix": "Configure \"rsyslog\" to log all cron messages by adding or updating
the following line to \"/etc/rsyslog.conf\":

cron.* /var/log/cron.log

Note: The line must be added before the following entry if it exists in
\"/etc/rsyslog.conf\":

*.* ~ # discards everything"

  describe.one do
    describe command("grep cron #{log_pkg_path}") do
      its('stdout.strip') { should match /^cron/ }
    end
    describe file("#{log_pkg_path}") do
      its('content') { should match /^\*\.\* \/var\/log\/messages\n?$/ }
      its('content') { should_not match /^*.*\s+~$.*^*\.\* \/var\/log\/messages\n?$/m}
    end
  end
end
