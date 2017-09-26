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

control "V-72299" do
  title "A File Transfer Protocol (FTP) server package must not be installed unless
needed."
  desc  "The FTP service provides an unencrypted remote access that does not provide
for the confidentiality and integrity of user passwords or the remote session. If a
privileged user were to log on using this service, the privileged user password
could be compromised. SSH or other encrypted file transfer methods must be used in
place of this service."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72299"
  tag "rid": "SV-86923r1_rule"
  tag "stig_id": "RHEL-07-040690"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify a lightweight FTP server has not been installed on the system.

Check to see if a lightweight FTP server has been installed with the following
commands:

# yum list installed lftpd
 lftp-4.4.8-7.el7.x86_64.rpm

If \"lftpd\" is installed and is not documented with the Information System Security
Officer (ISSO) as an operational requirement, this is a finding."
  tag "fix": "Document the \"lftpd\" package with the ISSO as an operational
requirement or remove it from the system with the following command:

# yum remove lftpd"

  describe package('lftpd') do
    it { should_not be_installed }
  end
end
