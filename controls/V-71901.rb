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

control "V-71901" do
  title "The operating system must initiate a session lock for graphical user
interfaces when the screensaver is activated."
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
  tag "gid": "V-71901"
  tag "rid": "SV-86525r1_rule"
  tag "stig_id": "RHEL-07-010110"
  tag "cci": "CCI-000057"
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "check": "Verify the operating system initiates a session lock a for graphical
user interfaces when the screensaver is activated. The screen program must be
installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

If GNOME is installed, check to see a session lock occurs when the screensaver is
activated with the following command:

# grep -i lock-delay /etc/dconf/db/local.d/*
lock-delay=uint32 5

If the \"lock-delay\" setting is missing, or is not set, this is a finding."
  tag "fix": "Configure the operating system to initiate a session lock for
graphical user interfaces when a screensaver is activated.

Create a database to contain the system-wide screensaver settings (if it does not
already exist) with the following command:

# touch /etc/dconf/db/local.d/00-screensaver

Add the setting to enable session locking when a screensaver is activated:

[org/gnome/desktop/screensaver]
lock-delay=uint32 5

After the setting has been set, run dconf update."

  describe command("grep -i lock-delay /etc/dconf/db/local.d/*") do
    its('stdout') { should match %r(^lock-delay=uint32 \d+\n?$) }
  end if package('gnome-desktop3').installed?

  describe "The system does not have GNOME installed" do
    skip "The system does not have GNOME installed, this requirement is Not
    Applicable."
  end if !package('gnome-desktop3').installed?
end
