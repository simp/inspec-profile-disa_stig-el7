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

control "V-71895" do
  title "The operating system must set the idle delay setting for all connection
types."
  desc  "
    A session time-out lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but does
not log out because of the temporary nature of the absence. Rather than relying on
the user to manually lock their operating system session prior to vacating the
vicinity, operating systems need to be able to identify when a user's session has
idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-71895"
  tag "rid": "SV-86519r3_rule"
  tag "stig_id": "RHEL-07-010080"
  tag "cci": "CCI-000057"
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "subsystems": ["gnome3"]
  desc "check", "Verify the operating system prevents a user from overriding session
lock after a 15-minute period of inactivity for graphical user interfaces. The
screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Determine which profile the system database is using with the following command:
#grep system-db /etc/dconf/profile/user

system-db:local

Check for the lock delay setting with the following command:

Note: The example below is using the database \"local\" for the system, so the path
is \"/etc/dconf/db/local.d\". This path must be modified if a database other than
\"local\" is being used.

# grep -i idle-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/idle-delay

If the command does not return a result, this is a finding."
  desc "fix", "Configure the operating system to prevent a user from overriding a
session lock after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not
already exist) with the following command:

Note: The example below is using the database \"local\" for the system, so if the
system is using another database in /etc/dconf/profile/user, the file should be
created under the appropriate subdirectory.

# touch /etc/dconf/db/local.d/locks/session

Add the setting to lock the screensaver idle delay:

/org/gnome/desktop/screensaver/idle-delay"

  describe command("grep -i idle-delay /etc/dconf/db/*/locks/*") do
    its('stdout.strip') { should_not cmp "" }
    its('stderr') { should_not match /.*No such file or directory\n?$/ }
  end
  only_if { package('gnome-desktop3').installed? }
end
