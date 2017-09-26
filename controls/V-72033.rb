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

control "V-72033" do
  title "All local initialization files must have mode 0740 or less permissive."
  desc  "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72033"
  tag "rid": "SV-86657r1_rule"
  tag "stig_id": "RHEL-07-020710"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that all local initialization files have a mode of \"0740\"
or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If any local initialization files have a mode more permissive than \"0740\", this is
a finding."
  tag "fix": "Set the mode of the local initialization files to \"0740\" with the
following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chmod 0740 /home/smithj/.<INIT_FILE>"

  # Assumption - users' home directories created in "home"
  # Allows for mode 740 or less permissive
  home_dirs = command('ls -d /home/*').stdout.split("\n")
  home_dirs.each do |home|
    home_files = command("find #{home} -xdev -maxdepth 1 -name '.*' -type f -perm /037").stdout.split("\n")
    home_files.each do |filename|
      describe file(filename) do
        it { should_not be_executable.by('group') }
        it { should_not be_writable.by('group') }
        it { should_not be_executable.by('others') }
        it { should_not be_writable.by('others') }
        it { should_not be_readable.by('others') }
      end
    end
  end
end
