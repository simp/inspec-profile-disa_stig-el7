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

control "V-71891" do
  title "The operating system must enable a user session lock until that user
re-establishes access using established identification and authentication
procedures."
  desc  "A session lock is a temporary action taken when a user stops work and moves away
from the immediate physical vicinity of the information system but does not want to
log out because of the temporary nature of the absence. The session lock is implemented
at the point where session activity can be determined. Regardless of where the
session lock is determined and implemented, once invoked, the session lock must
remain in place until the user reauthenticates. No other activity aside from
reauthentication must unlock the system."

if package('gnome-desktop3').installed?
  impact 0.5
else
  impact 0.0
end

  tag "gtitle": "SRG-OS-000028-GPOS-00009"
  tag "gid": "V-71891"
  tag "rid": "SV-86515r2_rule"
  tag "stig_id": "RHEL-07-010060"
  tag "cci": "CCI-000056"
  tag "nist": ["AC-11 b", "Rev_4"]
  tag "check": "Verify the operating system enables a user's session lock until that
user re-establishes access using established identification and authentication
procedures. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check to see if the screen lock is enabled with the following command:

# grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver
lock-enabled=true

If the \"lock-enabled\" setting is missing or is not set to \"true\", this is a
finding."
  tag "fix": "Configure the operating system to enable a user's session lock until
that user re-establishes access using established identification and authentication
procedures.

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

  describe parse_config_file('/etc/dconf/db/local.d/00-screensaver') do
    its('lock-enabled') { should cmp 'true' }
  end if package('gnome-desktop3').installed?

  describe "The system does not have GNOME installed" do
    skip "The system does not have GNOME installed, this requirement is Not
    Applicable."
  end if !package('gnome-desktop3').installed?
end
