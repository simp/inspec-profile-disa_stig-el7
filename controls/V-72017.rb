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

control "V-72017" do
  title "All local interactive user home directories must have mode 0750 or less
permissive."
  desc  "Excessive permissions on local interactive user home directories may allow
unauthorized access to user files by other users."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72017"
  tag "rid": "SV-86641r1_rule"
  tag "stig_id": "RHEL-07-020630"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the assigned home directory of all local interactive users
has a mode of \"0750\" or less permissive.

Check the home directory assignment for all non-privileged users on the system with
the following command:

Note: This may miss interactive users that have been assigned a privileged User
Identifier (UID). Evidence of interactive use may be obtained from a number of log
files containing system logon information.

# ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)
-rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj

If home directories referenced in \"/etc/passwd\" do not have a mode of \"0750\" or
less permissive, this is a finding."
  tag "fix": "Change the mode of interactive user’s home directories to \"0750\". To
change the mode of a local interactive user’s home directory, use the following
command:

Note: The example will be for the user \"smithj\".

# chmod 0750 /home/smithj"

  # Assumption - users' home directories created in "home"
  # Allows for mode 750 or less permissive
  home_dirs = command('ls -d /home/*').stdout.split("\n")
  home_dirs.each do |home|
    describe file(home) do
      it { should_not be_writable.by('group')}
      it { should_not be_executable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_readable.by('others') }
    end
  end
end
