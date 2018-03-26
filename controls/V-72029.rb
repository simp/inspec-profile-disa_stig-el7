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

control "V-72029" do
  title "All local initialization files for interactive users must be owned by the
home directory user or root."
  desc  "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72029"
  tag "rid": "SV-86653r1_rule"
  tag "stig_id": "RHEL-07-020690"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all local initialization files for interactive users are
owned by the home directory user or root.

Check the owner on all local initialization files with the following command:

Note: The example will be for the \"smithj\" user, who has a home directory of
\"/home/smithj\".

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .bash_profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .profile

If any file that sets a local interactive user’s environment variables to override
the system is not owned by the home directory owner or root, this is a finding."
  tag "fix": "Set the owner of the local initialization files for interactive users
to either the directory owner or root with the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chown smithj /home/smithj/.*"

  findings = []
  users.where{ uid >= 1000 and home != ""}.entries.each do |user_info|
    findings = findings + command("find #{user_info.home} -name '.*' -not -user #{user_info.username} -a -not -user root").stdout.split("\n")
  end
  describe findings do
    its ('length') { should == 0 }
  end
end
