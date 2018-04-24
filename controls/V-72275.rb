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

control "V-72275" do
  title "The system must display the date and time of the last successful account
logon upon logon."
  desc  "Providing users with feedback on when account accesses last occurred
facilitates user recognition and reporting of unauthorized account use."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72275"
  tag "rid": "SV-86899r1_rule"
  tag "stig_id": "RHEL-07-040530"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['pam', 'lastlog']
  tag "check": "Verify users are provided with feedback on when account accesses
last occurred.

Check that \"pam_lastlog\" is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/postlogin-ac

session     required      pam_lastlog.so showfailed silent

If \"pam_lastlog\" is missing from \"/etc/pam.d/postlogin-ac\" file, or the silent
option is present on the line check for the \"PrintLastLog\" keyword in the sshd
daemon configuration file, this is a finding."
  tag "fix": "Configure the operating system to provide users with feedback on when
account accesses last occurred by setting the required configuration options in
\"/etc/pam.d/postlogin-ac\".

Add the following line to the top of \"/etc/pam.d/postlogin-ac\":

session     required      pam_lastlog.so showfailed"

  describe sshd_config do
    its('PrintLastLog') { should_not cmp 'silent' }
  end

  describe pam('/etc/pam.d/postlogin') do
    its('lines') { should match_pam_rule('session .* pam_lastlog.so showfailed') }
  end
end
