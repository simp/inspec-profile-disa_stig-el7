# encoding: utf-8
#
control "V-71899" do
  title "The operating system must initiate a session lock for the screensaver
after a period of inactivity for graphical user interfaces."
  desc  "
    A session time-out lock is a temporary action taken when a user stops work
and moves away from the immediate physical vicinity of the information system
but does not log out because of the temporary nature of the absence. Rather
than relying on the user to manually lock their operating system session prior
to vacating the vicinity, operating systems need to be able to identify when a
user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.
  "
  if package('gnome-desktop3').installed?
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-71899"
  tag "rid": "SV-86523r3_rule"
  tag "stig_id": "RHEL-07-010100"
  tag "cci": ["CCI-000057"]
  tag "documentable": false
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "subsystems": ["gnome3", "session", "lock"]
  desc "check", "Verify the operating system initiates a session lock after a
15-minute period of inactivity for graphical user interfaces. The screen
program must be installed to lock sessions on the console.

If it is installed, GNOME must be configured to enforce a session lock after a
15-minute delay. Check for the session lock settings with the following
commands:

# grep -i  idle-activation-enabled /etc/dconf/db/local.d/*

idle-activation-enabled=true

If \"idle-activation-enabled\" is not set to \"true\", this is a finding."
  desc "fix", "Configure the operating system to initiate a session lock after a
15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does
not already exist) with the following command:

# touch /etc/dconf/db/local.d/00-screensaver

Add the setting to enable screensaver locking after 15 minutes of inactivity:

[org/gnome/desktop/screensaver]

idle-activation-enabled=true

Update the system databases:

# dconf update

Users must log out and back in again before the system-wide settings take
effect."
  tag "fix_id": "F-78251r2_fix"

  describe command('gsettings get org.gnome.desktop.screensaver idle-activation-enabled') do
    its('stdout.strip') { should cmp 'true' }
  end if package('gnome-desktop3').installed?

  describe "The system does not have GNOME installed" do
    skip "The system does not have GNOME installed, this requirement is Not
    Applicable."
  end if !package('gnome-desktop3').installed?
end
