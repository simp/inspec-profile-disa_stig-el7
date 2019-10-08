# encoding: utf-8
#

system_activity_timeout = input(
'system_activity_timeout',
value: 600,
description: 'The length of inactivity from the user in which the network connections associated with a session in terminated.'
)

control "V-72223" do
  title "All network connections associated with a communication session must
be terminated at the end of the session or after 10 minutes of inactivity from
the user at a command prompt, except to fulfill documented and validated
mission requirements."
  desc  "
    Terminating an idle session within a short time period reduces the window
of opportunity for unauthorized personnel to take control of a management
session enabled on the console or console port that has been left unattended.
In addition, quickly terminating an idle session will also free up resources
committed by the managed network element.

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
  tag "gid": "V-72223"
  tag "rid": "SV-86847r3_rule"
  tag "stig_id": "RHEL-07-040160"
  tag "cci": ["CCI-001133", "CCI-002361"]
  tag "documentable": false
  tag "nist": ["SC-10", "AC-12", "Rev_4"]
  tag "subsystems": ['user_profile']
  desc "check", "Verify the operating system terminates all network connections
associated with a communications session at the end of the session or based on
inactivity.

Check the value of the system inactivity timeout with the following command:

# grep -i tmout /etc/bashrc /etc/profile.d/*

TMOUT=600

If \"TMOUT\" is not set to \"600\" or less in \"/etc/bashrc\" or in a script
created to enforce session termination after inactivity, this is a finding."
  desc "fix", "Configure the operating system to terminate all network
connections associated with a communications session at the end of the session
or after a period of inactivity.

Add or update the following lines in \"/etc/profile\".

TMOUT=600
readonly TMOUT
export TMOUT

Or create a script to enforce the inactivity timeout (for example
/etc/profile.d/tmout.sh) such as:

#!/bin/bash

TMOUT=600
readonly TMOUT
export TMOUT"
  tag "fix_id": "F-78577r4_fix"

  bashrc_file = parse_config_file('/etc/bashrc')

  describe.one do
    describe bashrc_file do
      its('TMOUT') { should cmp <= system_activity_timeout }
    end

    profiled_files = command("find /etc/profile.d/*").stdout.split("\n")
    profiled_files.each do |file|
      profile_file = parse_config_file(file)
      describe profile_file do
        its('TMOUT') { should cmp <= system_activity_timeout }
      end
    end
  end
end
