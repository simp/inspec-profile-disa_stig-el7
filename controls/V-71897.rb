# encoding: utf-8
#
control "V-71897" do
  title "The operating system must have the screen package installed."
  desc  "
    A session time-out lock is a temporary action taken when a user stops work
and moves away from the immediate physical vicinity of the information system
but does not log out because of the temporary nature of the absence. Rather
than relying on the user to manually lock their operating system session prior
to vacating the vicinity, operating systems need to be able to identify when a
user's session has idled and take action to initiate the session lock.

    The screen package allows for a session lock to be implemented and
configured.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-71897"
  tag "rid": "SV-86521r1_rule"
  tag "stig_id": "RHEL-07-010090"
  tag "cci": ["CCI-000057"]
  tag "documentable": false
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "subsystems": ["screen", "lock", "session"]
  desc "check", "Verify the operating system has the screen package installed.

Check to see if the screen package is installed with the following command:

# yum list installed | grep screen
screen-4.3.1-3-x86_64.rpm

If is not installed, this is a finding."
  desc "fix", "Install the screen package to allow the initiation a session lock
after a 15-minute period of inactivity for graphical users interfaces.

Install the screen program (if it is not on the system) with the following
command:

# yum install screen

The console can now be locked with the following key combination:

ctrl+A x"
  tag "fix_id": "F-78249r1_fix"
  describe package('screen') do
    it { should be_installed }
  end
end
