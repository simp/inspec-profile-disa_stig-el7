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

control "V-72241" do
  title "All network connections associated with SSH traffic must terminate after a
period of inactivity."
  desc  "
    Terminating an idle SSH session within a short time period reduces the window of
opportunity for unauthorized personnel to take control of a management session
enabled on the console or console port that has been left unattended. In addition,
quickly terminating an idle SSH session will also free up resources committed by the
managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at the
operating system level and de-allocating networking assignments at the application
level if multiple application sessions are using a single operating system-level
network connection. This does not mean that the operating system terminates all
sessions or network access; it only ends the inactive session and releases the
resources associated with that session.

    Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-0010.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000163-GPOS-00072"
  tag "gid": "V-72241"
  tag "rid": "SV-86865r2_rule"
  tag "stig_id": "RHEL-07-040340"
  tag "cci": "CCI-001133"
  tag "nist": ["SC-10", "Rev_4"]
  tag "cci": "CCI-002361"
  tag "nist": ["AC-12", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the operating system automatically terminates a user session
after inactivity time-outs have expired.

Check for the value of the \"ClientAliveCountMax\" keyword with the following
command:

# grep -i clientalivecount /etc/ssh/sshd_config
ClientAliveCountMax 0

If \"ClientAliveCountMax\" is not set to \"0\" in \"/etc/ssh/sshd_config\", this is
a finding."
  tag "fix": "Configure the operating system to automatically terminate a user
session after inactivity time-outs have expired or at shutdown.

Add the following line (or modify the line to have the required value) to the
\"/etc/ssh/sshd_config\" file (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party
vendor):

ClientAliveCountMax 0

The SSH service must be restarted for changes to take effect."

  describe sshd_config do
    its('ClientAliveCountMax') { should cmp '0' }
  end
end
