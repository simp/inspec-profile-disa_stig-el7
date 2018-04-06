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

control "V-72209" do
  title "The system must send rsyslog output to a log aggregation server."
  desc  "Sending rsyslog output to another system ensures that the logs cannot be
removed or modified in the event that the system is compromised or has a hardware
failure."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72209"
  tag "rid": "SV-86833r1_rule"
  tag "stig_id": "RHEL-07-031000"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'rsyslog']
  tag "check": "Verify \"rsyslog\" is configured to send all messages to a log
aggregation server.

Check the configuration of \"rsyslog\" with the following command:

Note: If another logging package is used, substitute the utility configuration file
for \"/etc/rsyslog.conf\".

# grep @ /etc/rsyslog.conf
*.* @@logagg.site.mil

If there are no lines in the \"/etc/rsyslog.conf\" file that contain the \"@\" or
\"@@\" symbol(s), and the lines with the correct symbol(s) to send output to another
system do not cover all \"rsyslog\" output, ask the System Administrator to indicate
how the audit logs are off-loaded to a different system or media.

If there is no evidence that the audit logs are being sent to another system, this
is a finding."
  tag "fix": "Modify the \"/etc/rsyslog.conf\" file to contain a configuration line
to send all \"rsyslog\" output to a log aggregation system:

*.* @@<log aggregation system name>"

  describe command("grep @ #{log_pkg_path}") do
    its('stdout.strip') { should_not be_empty }
  end
end
