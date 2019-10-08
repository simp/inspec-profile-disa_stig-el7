# encoding: utf-8
#
control "V-73161" do
  title "File systems that are being imported via Network File System (NFS)
must be mounted to prevent binary files from being executed."
  desc  "The \"noexec\" mount option causes the system to not execute binary
files. This option must be used for mounting any file system not containing
approved binary files as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73161"
  tag "rid": "SV-87813r1_rule"
  tag "stig_id": "RHEL-07-021021"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['nfs']
  desc "check", "Verify file systems that are being NFS exported are mounted
with the \"noexec\" option.

Find the file system(s) that contain the directories being exported with the
following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,noexec 0 0

If a file system found in \"/etc/fstab\" refers to NFS and it does not have the
\"noexec\" option set, and use of NFS exported binaries is not documented with
the Information System Security Officer (ISSO) as an operational requirement,
this is a finding."
  desc "fix", "Configure the \"/etc/fstab\" to use the \"noexec\" option on file
systems that are being exported via NFS."
  tag "fix_id": "F-79607r1_fix"

  nfs_systems = etc_fstab.nfs_file_systems.entries
  if !nfs_systems.nil? and !nfs_systems.empty?
    nfs_systems.each do |file_system|
      describe file_system do
        its ('mount_options') { should include 'noexec' }
      end
    end
  else
    describe "No NFS file systems were found." do
      subject { nfs_systems.nil? or nfs_systems.empty? }
      it { should eq true }
    end
  end
end
