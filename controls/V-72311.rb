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

control "V-72311" do
  title "The Network File System (NFS) must be configured to use RPCSEC_GSS."
  desc  "When an NFS server is configured to use RPCSEC_SYS, a selected userid and
groupid are used to handle requests from the remote user. The userid and groupid
could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of
authentication uses certificates on the server and client systems to more securely
authenticate the remote mount request."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72311"
  tag "rid": "SV-86935r3_rule"
  tag "stig_id": "RHEL-07-040750"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify \"AUTH_GSS\" is being used to authenticate NFS mounts.

To check if the system is importing an NFS file system, look for any entries in the
\"/etc/fstab\" file that have a file system type of \"nfs\" with the following
command:

# cat /etc/fstab | grep nfs
192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=krb5:krb5i:krb5p

If the system is mounting file systems via NFS and has the sec option without the
\"krb5:krb5i:krb5p\" settings, the \"sec\" option has the \"sys\" setting, or the
\"sec\" option is missing, this is a finding."
  tag "fix": "Update the \"/etc/fstab\" file so the option \"sec\" is defined for
each NFS mounted file system and the \"sec\" option does not have the \"sys\"
setting.

Ensure the \"sec\" option is defined as \"krb5:krb5i:krb5p\"."

  nfs_systems = etc_fstab.nfs_file_systems.entries
  nfs_systems.each do |file_system|
    describe file_system do
      its ('mount_options') { should include 'sec=krb5:krb5i:krb5p' }
    end
  end
end
