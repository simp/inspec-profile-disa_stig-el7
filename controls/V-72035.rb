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

control "V-72035" do
  title "All local interactive user initialization files executable search paths
must contain only paths that resolve to the users home directory."
  desc  "The executable search path (typically the PATH environment variable)
contains a list of directories for the shell to search to find executables. If this
path includes the current working directory (other than the user’s home directory),
executables in these directories may be executed instead of system commands. This
variable is formatted as a colon-separated list of directories. If there is an empty
entry, such as a leading or trailing colon or two consecutive colons, this is
interpreted as the current working directory. If deviations from the default system
search path for the local interactive user are required, they must be documented
with the Information System Security Officer (ISSO)."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72035"
  tag "rid": "SV-86659r2_rule"
  tag "stig_id": "RHEL-07-020720"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that all local interactive user initialization files'
executable search path statements do not contain statements that will reference a
working directory other than the users’ home directory.

Check the executable search path statement for all local interactive user
initialization files in the users' home directory with the following commands:

Note: The example will be for the smithj user, which has a home directory of
\"/home/smithj\".

# grep -i path /home/smithj/.*
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

If any local interactive user initialization files have executable search path
statements that include directories outside of their home directory, this is a
finding."
  tag "fix": "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that contain user home directories for interactive users."

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  findings = Set[]
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    grep_results =  command("grep -i path --exclude=\".bash_history\" #{user_info.home}/.*").stdout.split("\\n")
    grep_results.each do |result|
      result.slice! "PATH="
      # Case when last value in exec search path is :
      if result[-1] == ":" then
        result = result + " "
      end
      result.slice! "$PATH:"
      result.gsub! '$HOME', "#{user_info.home}"
      result.gsub! '~', "#{user_info.home}"
      line_arr = result.split(":")
      line_arr.delete_at(0)
      line_arr.each do |line|
        # Don't run test on line that exports PATH and is not commented out
        if !line.start_with?('export') && !line.start_with?('#') then
          # Case when :: found in exec search path or : found at beginning
          if line.strip.empty? then
            curr_work_dir = command("pwd").stdout.gsub("\n", "")
            if curr_work_dir.start_with?("#{user_info.home}") then
              line = curr_work_dir
            end
          end
          # This will fail if non-home directory found in path
          if !line.start_with?(user_info.home)
            findings.add(line)
          end
        end
      end
    end
  end
  describe.one do
    describe etc_fstab do
      its('home_mount_options') { should include 'nosuid' }
    end
    describe "Initialization files that include executable search paths that include directories outside their home directories" do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end
