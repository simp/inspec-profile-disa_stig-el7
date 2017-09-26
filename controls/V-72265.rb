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

control "V-72265" do
  title "The SSH daemon must use privilege separation."
  desc  "SSH daemon privilege separation causes the SSH process to drop root
privileges when not needed, which would decrease the impact of software
vulnerabilities in the unprivileged section."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72265"
  tag "rid": "SV-86889r2_rule"
  tag "stig_id": "RHEL-07-040460"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the SSH daemon performs privilege separation.

Check that the SSH daemon performs privilege separation with the following command:

# grep -i usepriv /etc/ssh/sshd_config

UsePrivilegeSeparation sandbox

If the \"UsePrivilegeSeparation\" keyword is set to \"no\", is missing, or the
retuned line is commented out, this is a finding."
  tag "fix": "Uncomment the \"UsePrivilegeSeparation\" keyword in
\"/etc/ssh/sshd_config\" (this file may be named differently or be in a different
location if using a version of SSH that is provided by a third-party vendor) and set
the value to \"sandbox\" or \"yes\":

UsePrivilegeSeparation sandbox

The SSH service must be restarted for changes to take effect."

  describe.one do
    describe sshd_config do
      its('UsePrivilegeSeparation') { should cmp 'sandbox' }
    end
    describe sshd_config do
      its('UsePrivilegeSeparation') { should cmp 'yes' }
    end
  end
end
