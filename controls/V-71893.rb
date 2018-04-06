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

control "V-71893" do
  title "The operating system must initiate a screensaver after a 15-minute period
of inactivity for graphical user interfaces."
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
if package('gnome-desktop3').installed?
  impact 0.5
else
  impact 0.0
end

  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-71893"
  tag "rid": "SV-86517r2_rule"
  tag "stig_id": "RHEL-07-010070"
  tag "cci": "CCI-000057"
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "check": "Verify the operating system initiates a screensaver after a
15-minute period of inactivity for graphical user interfaces. The screen program
must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check to see if GNOME is configured to display a screensaver after a 15 minute delay
with the following command:

# grep -i idle-delay /etc/dconf/db/local.d/*
idle-delay=uint32 900

If the \"idle-delay\" setting is missing or is not set to \"900\" or less, this is a
finding."
  tag "fix": "Configure the operating system to initiate a screensaver after a
15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not
already exist) with the following command:

# touch /etc/dconf/db/local.d/00-screensaver

Edit “org/gnome/desktop/session” and add or update the following lines:

# Set the lock time out to 900 seconds before the session is considered idle
idle-delay=uint32 900

Edit \"org/gnome/desktop/screensaver\" and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true
# Set the lock timeout to 180 seconds after the screensaver has been activated
lock-delay=uint32 180

You must include the \"uint32\" along with the integer key values as shown.

Override the user's setting and prevent the user from changing it by editing
“/etc/dconf/db/local.d/locks/screensaver” and adding or updating the following lines:

# Lock desktop screensaver settings
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay

Update the system databases:

# dconf update

Users must log out and back in again before the system-wide settings take effect."

  describe command("grep -i idle-delay /etc/dconf/db/local.d/*") do
    its('stdout') { should match %r{^idle-delay=unit32 (900|[0-8]\d\d|\d\d|\d|)\n?$} }
  end if package('gnome-desktop3').installed?

  describe "The system does not have GNOME installed" do
    skip "The system does not have GNOME installed, this requirement is Not
    Applicable."
  end if !package('gnome-desktop3').installed?
end
