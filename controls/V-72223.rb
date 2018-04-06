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

SYSTEM_INACTIVITY_TIMEOUT = attribute(
'system_activity_timeout',
default: 600,
description: 'The length of inactivity from the user in which the network connections associated with a session in terminated.'
)

control "V-72223" do
  title "All network connections associated with a communication session must be
terminated at the end of the session or after 10 minutes of inactivity from the user
at a command prompt, except to fulfill documented and validated mission
requirements."
  desc  "
    Terminating an idle session within a short time period reduces the window of
opportunity for unauthorized personnel to take control of a management session
enabled on the console or console port that has been left unattended. In addition,
quickly terminating an idle session will also free up resources committed by the
managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at the
operating system level and de-allocating networking assignments at the application
level if multiple application sessions are using a single operating system-level
network connection. This does not mean that the operating system terminates all
sessions or network access; it only ends the inactive session and releases the
resources associated with that session.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000163-GPOS-00072"
  tag "gid": "V-72223"
  tag "rid": "SV-86847r2_rule"
  tag "stig_id": "RHEL-07-040160"
  tag "cci": ["CCI-001133","CCI-002361"]
  tag "nist": ["SC-10","AC-12","Rev_4"]
  tag "check": "Verify the operating system terminates all network connections
associated with a communications session at the end of the session or based on
inactivity.

Check the value of the system inactivity timeout with the following command:

# grep -i tmout /etc/bashrc
TMOUT=600

If \"TMOUT\" is not set to \"600\" or less in \"/etc/bashrc\", this is a finding."
  tag "fix": "Configure the operating system to terminate all network connections
associated with a communications session at the end of the session or after a period
of inactivity.

Add the following line to \"/etc/profile\" (or modify the line to have the required
value):

TMOUT=600

The SSH service must be restarted for changes to take effect."

bashrc_file = parse_config_file('/etc/bashrc')

  describe bashrc_file do
    its('TMOUT') { should_not eq nil }
  end
  describe bashrc_file.params('TMOUT') do
    it { should cmp <= SYSTEM_INACTIVITY_TIMEOUT }
  end 

end
