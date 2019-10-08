# encoding: utf-8
#

log_aggregation_server = input(
  'log_aggregation_server',
  description: 'The system is intented to be a log aggregation server.',
  value: false
)

# TODO account for using other log systems. `syslog-ng`
# TODO add attribute for `SYSLOG_SYSTEM` and adjust control logic

control "V-72211" do
  title "The rsyslog daemon must not accept log messages from other servers
unless the server is being used for log aggregation."
  desc  "
    Unintentionally running a rsyslog server accepting remote messages puts the
system at increased risk. Malicious rsyslog messages sent to the server could
exploit vulnerabilities in the server software itself, could introduce
misleading information in to the system's logs, or could fill the system's
storage leading to a Denial of Service.
    If the system is intended to be a log aggregation server its use must be
documented with the ISSO.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72211"
  tag "rid": "SV-86835r1_rule"
  tag "stig_id": "RHEL-07-031010"
  tag "cci": ["CCI-000318", "CCI-000368", "CCI-001812", "CCI-001813",
"CCI-001814"]
  tag "documentable": false
  tag "nist": ["CM-3 f", "CM-6 c", "CM-11 (2)", "CM-5 (1)", "CM-5 (1)", "Rev_4"]
  tag "subsystems": ['rsyslog']
  desc "check", "Verify that the system is not accepting \"rsyslog\" messages
from other systems unless it is documented as a log aggregation server.

Check the configuration of \"rsyslog\" with the following command:

# grep imtcp /etc/rsyslog.conf
ModLoad imtcp

If the \"imtcp\" module is being loaded in the \"/etc/rsyslog.conf\" file, ask
to see the documentation for the system being used for log aggregation.

If the documentation does not exist, or does not specify the server as a log
aggregation system, this is a finding."
  desc "fix", "Modify the \"/etc/rsyslog.conf\" file to remove the \"ModLoad
imtcp\" configuration line, or document the system as being used for log
aggregation."
  tag "fix_id": "F-78565r1_fix"

  if log_aggregation_server
    describe file('/etc/rsyslog.conf') do
      its('content') { should match %r{^\$ModLoad\s+imtcp.*\n?$} }
    end
  else
    describe.one do
      describe file('/etc/rsyslog.conf') do
        its('content') { should match %r{\$ModLoad\s+imtcp.*\n?$} }
      end
      describe file('/etc/rsyslog.conf') do
        its('content') { should_not match %r{^\$ModLoad\s+imtcp.*\n?$} }
      end
    end
  end
end
