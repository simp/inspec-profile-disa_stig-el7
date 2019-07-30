# encoding: utf-8

disable_slow_controls = attribute(
  'disable_slow_controls',
  value: false,
  description: 'If enabled, this attribute disables this control and other
                controls that consistently take a long time to complete.'
)

exempt_home_users = attribute(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  value: []
)

non_interactive_shells = attribute(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  value: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync", "/bin/true"]
)

control "V-72037" do
  title "Local initialization files must not execute world-writable programs."
  if disable_slow_controls
    desc "This control consistently takes a long to run and has been disabled
          using the disable_slow_controls attribute."
  else
  desc  "If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user
files or otherwise compromise the system at the user level. If the system is
compromised at the user level, it is easier to elevate privileges to eventually
compromise the system at the root and network level."
  end
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72037"
  tag "rid": "SV-86661r1_rule"
  tag "stig_id": "RHEL-07-020730"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that local initialization files do not execute
world-writable programs.

Check the system for world-writable files with the following command:

# find / -perm -002 -type f -exec ls -ld {} \\; | more

For all files listed, check for their presence in the local initialization
files with the following commands:

Note: The example will be for a system that is configured to create users’ home
directories in the \"/home\" directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files,
this is a finding."
  tag "fix": "Set the mode on files being executed by the local initialization
files with the following command:

# chmod 0755  <file>"
  tag "fix_id": "F-78389r1_fix"

  if disable_slow_controls
    describe "This control consistently takes a long to run and has been disabled
  using the disable_slow_controls attribute." do
      skip "This control consistently takes a long to run and has been disabled
  using the disable_slow_controls attribute. You must enable this control for a
  full accredidation for production."
  end
  else
    ignore_shells = non_interactive_shells.join('|')

    #Get home directory for users with UID >= 1000 or UID == 0 and support interactive logins.
    dotfiles = Set[]
    u = users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries
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
        count = command("grep -c \"#{ww_file}\" \"#{dotfile}\"").stdout.strip.to_i
        findings << dotfile if count > 0
      end
    end
    describe "Local initialization files that are found to reference world-writable files" do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end
