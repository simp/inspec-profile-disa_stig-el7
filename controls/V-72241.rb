# encoding: utf-8
#
control "V-72241" do
  title "All network connections associated with SSH traffic must terminate
after a period of inactivity."
  desc  "
    Terminating an idle SSH session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended. In addition, quickly terminating an idle SSH session will also free
up resources committed by the managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at
the operating system level and de-allocating networking assignments at the
application level if multiple application sessions are using a single operating
system-level network connection. This does not mean that the operating system
terminates all sessions or network access; it only ends the inactive session
and releases the resources associated with that session.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000163-GPOS-00072"
  tag "satisfies": ["SRG-OS-000163-GPOS-00072", "SRG-OS-000279-GPOS-00109"]
  tag "gid": "V-72241"
  tag "rid": "SV-86865r3_rule"
  tag "stig_id": "RHEL-07-040340"
  tag "cci": ["CCI-001133", "CCI-002361"]
  tag "documentable": false
  tag "nist": ["SC-10", "AC-12", "Rev_4"]
  tag "subsystems": ["ssh"]
  desc "check", "Check the version of the operating system with the following
command:

# cat /etc/redhat-release

If the release is 7.4 or newer this requirement is Not Applicable.

Verify the operating system automatically terminates a user session after
inactivity time-outs have expired.

Check for the value of the \"ClientAliveCountMax\" keyword with the following
command:

# grep -i clientalivecount /etc/ssh/sshd_config
ClientAliveCountMax 0

If \"ClientAliveCountMax\" is not set to \"0\" in \"/etc/ ssh/sshd_config\",
this is a finding."
  desc "fix", "Configure the operating system to automatically terminate a user
session after inactivity time-outs have expired or at shutdown.

Add the following line (or modify the line to have the required value) to the
\"/etc/ssh/sshd_config\" file (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party
vendor):

ClientAliveCountMax 0

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78595r3_fix"

  if os.release.to_f >= 7.4
    impact 0.0
    describe "The release is #{os.release}" do
      skip "The release is newer than 7.4; this control is Not Applicable."
    end
  else
    describe sshd_config do
      its('ClientAliveCountMax') { should cmp '0' }
    end
  end
end
