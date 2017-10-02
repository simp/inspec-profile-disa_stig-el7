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

control "V-72049" do
  title "The umask must be set to 077 for all local interactive user accounts."
  desc  "The umask controls the default access mode assigned to newly created files.
A umask of 077 limits new files to mode 700 or less permissive. Although umask can
be represented as a four-digit number, the first digit representing special access
modes is typically ignored or required to be \"0\". This requirement applies to the
globally configured system defaults and the local interactive user defaults for each
account on the system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72049"
  tag "rid": "SV-86673r1_rule"
  tag "stig_id": "RHEL-07-021040"
  tag "cci": "CCI-000318"
  tag "nist": ["CM-3 f", "Rev_4"]
  tag "cci": "CCI-000368"
  tag "nist": ["CM-6 c", "Rev_4"]
  tag "cci": "CCI-001812"
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "cci": "CCI-001813"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "cci": "CCI-001814"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "Verify that the default umask for all local interactive users is
\"077\".

Identify the locations of all local interactive user home directories by looking at
the \"/etc/passwd\" file.

Check all local interactive user initialization files for interactive users with the
following command:

Note: The example is for a system that is configured to create users home
directories in the \"/home\" directory.

# grep -i umask /home/*/.*

If any local interactive user initialization files are found to have a umask
statement that has a value less restrictive than \"077\", this is a finding."
  tag "fix": "Remove the umask statement from all local interactive users’
initialization files.

If the account is for an application, the requirement for a umask less restrictive
than \"077\" can be documented with the Information System Security Officer, but the
user agreement for access to the account must specify that the local interactive
user must log on to their account first and then switch the user to the application
account with the correct option to gain the account’s environment variables."

  file_lines = command('grep -i -s umask /home/*/.*').stdout.split("\n")
  file_lines.each do |curr_line|
    file_name = curr_line.split(':').first
    describe command("grep -i umask #{file_name}") do
      its('stdout.strip') { should match /^umask\s+.*077/}
    end
  end
end
