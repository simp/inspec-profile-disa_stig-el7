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

control "V-72245" do
  title "The system must display the date and time of the last successful account
logon upon an SSH logon."
  desc  "Providing users with feedback on when account accesses via SSH last
occurred facilitates user recognition and reporting of unauthorized account use."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72245"
  tag "rid": "SV-86869r2_rule"
  tag "stig_id": "RHEL-07-040360"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify SSH provides users with feedback on when account accesses
last occurred.

Check that \"PrintLastLog\" keyword in the sshd daemon configuration file is used
and set to \"yes\" with the following command:

# grep -i printlastlog /etc/ssh/sshd_config
PrintLastLog yes

If the \"PrintLastLog\" keyword is set to \"no\", is missing, or is commented out,
this is a finding."
  tag "fix": "Configure SSH to provide users with feedback on when account accesses
last occurred by setting the required configuration options in \"/etc/pam.d/sshd\"
or in the \"sshd_config\" file used by the system (\"/etc/ssh/sshd_config\" will be
used in the example) (this file may be named differently or be in a different
location if using a version of SSH that is provided by a third-party vendor).

Add the following line to the top of \"/etc/pam.d/sshd\":

session     required      pam_lastlog.so showfailed

Or modify the \"PrintLastLog\" line in \"/etc/ssh/sshd_config\" to match the
following:

PrintLastLog yes

The SSH service must be restarted for changes to \"sshd_config\" to take effect."

  describe sshd_config do
    its('PrintLastLog') { should cmp 'yes' }
  end
end
