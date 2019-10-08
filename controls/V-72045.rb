# encoding: utf-8
#
control "V-72045" do
  title "File systems that are being imported via Network File System (NFS)
must be mounted to prevent files with the setuid and setgid bit set from being
executed."
  desc  "The \"nosuid\" mount option causes the system to not execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72045"
  tag "rid": "SV-86669r1_rule"
  tag "stig_id": "RHEL-07-021020"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystem": ['nfs', 'file_system']
  desc "check", "Verify file systems that are being NFS exported are mounted
with the \"nosuid\" option.

Find the file system(s) that contain the directories being exported with the
following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs
rw,nosuid                                                    0 0

If a file system found in \"/etc/fstab\" refers to NFS and it does not have the
\"nosuid\" option set, this is a finding."
  desc "fix", "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that are being exported via NFS."
  tag "fix_id": "F-78397r1_fix"

  nfs_systems = etc_fstab.nfs_file_systems.entries
  if !nfs_systems.nil? and !nfs_systems.empty?
    nfs_systems.each do |partition|
      describe partition do
        its('mount_options') { should include 'nosuid' }
      end
    end
  else
    describe "No NFS file systems were found." do
      subject { nfs_systems.nil? or nfs_systems.empty? }
      it { should eq true }
    end
  end
end
