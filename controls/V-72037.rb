# encoding: utf-8
RUN_SLOW_CONTROL = attribute('run_slow_control', default: 'false',
description: 'Only run this control if it is enabled because it
searches the entire file system and does a lot of comparisons and
may take over 10 minutes to complete.')

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
  only_if {RUN_SLOW_CONTROL == 'true'}
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
  #Get home directory for users with UID >= 1000.
  dotfiles = Set[]
  u = users.where{uid >= 1000 and home != ""}.entries
  #For each user, build and execute a find command that identifies initialization files
  #in a user's home directory.
  u.each do |user|
    dotfiles = dotfiles + command("find #{user.home} -xdev -maxdepth 2 -name '.*' -type f").stdout.split("\n")
  end
  ww_files = Set[]
  ww_files = command('find / -perm -002 -type f -exec ls {} \;').stdout.lines
  #Check each dotfile for existence of each world-writeable file
  findings = Set[]
  dotfiles.each do |dotfile|
    dotfile = dotfile.strip
    ww_files.each do |ww_file|
      ww_file = ww_file.strip
      count = command("grep -c #{ww_file} #{dotfile}").stdout
        findings << dotfile
      end
    end
  end
  describe findings do
    its ('length') { should == 0 }
  end
end
