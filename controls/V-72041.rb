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

control "V-72041" do
  title "File systems that contain user home directories must be mounted to prevent
files with the setuid and setgid bit set from being executed."
  desc  "The \"nosuid\" mount option causes the system to not execute setuid and
setgid files with owner privileges. This option must be used for mounting any file
system not containing approved setuid and setguid files. Executing files from
untrusted file systems increases the opportunity for unprivileged users to attain
unauthorized administrative access."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72041"
  tag "rid": "SV-86665r2_rule"
  tag "stig_id": "RHEL-07-021000"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify file systems that contain user home directories are mounted
with the \"nosuid\" option.

Find the file system(s) that contain the user home directories with the following
command:

Note: If a separate file system has not been created for the user home directories
(user home directories are mounted under \"/\"), this is not a finding as the
\"nosuid\" option cannot be used on the \"/\" system.

# cut -d: -f 1,6 /etc/passwd | egrep \":[1-4][0-9]{3}\"
smithj:/home/smithj
thomasr:/home/thomasr

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4
rw,relatime,discard,data=ordered,nosuid 0 2

If a file system found in \"/etc/fstab\" refers to the user home directory file
system and it does not have the \"nosuid\" option set, this is a finding."
  tag "fix": "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that contain user home directories."

  # Assumption - users' home directories created in "home"
  describe mount('/home') do
    its('options') { should include 'nosuid' }
  end
end
