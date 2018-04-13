# encoding: utf-8
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

DISABLE_SLOW_CONTROLS = attribute(
  'disable_slow_controls',
  default: false,
  description: 'If enabled, this attribute disables this control and other
                controls that consistently take a long time to complete.'
)

EXEMPT_HOME_USERS = attribute(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  default: []
)

NON_INTERACTIVE_SHELLS = attribute(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  default: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync"]
)

control "V-72037" do
  title "Local initialization files must not execute world-writable programs."
  if DISABLE_SLOW_CONTROLS
    desc "This control consistently takes a long to run and has been disabled
          using the DISABLE_SLOW_CONTROLS attribute."
  else
    desc  "If user start-up files execute world-writable programs, especially in
           unprotected directories, they could be maliciously modified to destroy
           user files or otherwise compromise the system at the user level. If
           the system is compromised at the user level, it is easier to elevate
           privileges to eventually compromise the system at the root and
           network level."
  end
  impact 0.5
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

  if DISABLE_SLOW_CONTROLS
    describe "This control consistently takes a long to run and has been disabled
  using the DISABLE_SLOW_CONTROLS attribute." do
      skip "This control consistently takes a long to run and has been disabled
  using the DISABLE_SLOW_CONTROLS attribute. You must enable this control for a
  full accredidation for production."
  end
  else
    IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

    #Get home directory for users with UID >= 1000 or UID == 0 and support interactive logins.
    dotfiles = Set[]
    u = users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries
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
