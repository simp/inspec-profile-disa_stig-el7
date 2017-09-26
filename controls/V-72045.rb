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

control "V-72045" do
  title "File systems that are being imported via Network File System (NFS) must be
mounted to prevent files with the setuid and setgid bit set from being executed."
  desc  "The \"nosuid\" mount option causes the system to not execute \"setuid\" and
\"setgid\" files with owner privileges. This option must be used for mounting any
file system not containing approved \"setuid\" and \"setguid\" files. Executing
files from untrusted file systems increases the opportunity for unprivileged users
to attain unauthorized administrative access."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72045"
  tag "rid": "SV-86669r1_rule"
  tag "stig_id": "RHEL-07-021020"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify file systems that are being NFS exported are mounted with the
\"nosuid\" option.

Find the file system(s) that contain the directories being exported with the
following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs
rw,nosuid                                                    0 0

If a file system found in \"/etc/fstab\" refers to NFS and it does not have the
\"nosuid\" option set, this is a finding."
  tag "fix": "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that are being exported via NFS."

  mnt_lines = command('cat /etc/fstab | grep nfs').stdout.split("\n")
  mnt_lines.each do |mnt|
    mnt_arr = mnt.gsub(/\s+/m, ' ').strip.split(" ")
    describe mount("#{mnt_arr[1]}") do
      its('options') { should include 'nosuid' }
    end
  end
end
