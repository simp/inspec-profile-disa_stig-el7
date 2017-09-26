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

control "V-72037" do
  title "Local initialization files must not execute world-writable programs."
  desc  "If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user files or
otherwise compromise the system at the user level. If the system is compromised at
the user level, it is easier to elevate privileges to eventually compromise the
system at the root and network level."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72037"
  tag "rid": "SV-86661r1_rule"
  tag "stig_id": "RHEL-07-020730"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that local initialization files do not execute world-writable
programs.

Check the system for world-writable files with the following command:

# find / -perm -002 -type f -exec ls -ld {} \\; | more

For all files listed, check for their presence in the local initialization files
with the following commands:

Note: The example will be for a system that is configured to create users’ home
directories in the \"/home\" directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files, this
is a finding."
  tag "fix": "Set the mode on files being executed by the local initialization files
with the following command:

# chmod 0755  <file>"

  # Assumption - users' home directories created in "home"
  dotfiles = command('find /home -xdev -maxdepth 2 -name ".*" -type f').stdout.lines
  ww_files = command('find / -perm -002 -type f -exec ls {} \;').stdout.lines

  # check each dotfile for existance of each world-writeable file
  dotfiles.each do |dotfile|
    describe file(dotfile.strip) do
      ww_files.each do |ww_file|
        its('content') { should_not include ww_file.strip }
      end
    end
  end
end
