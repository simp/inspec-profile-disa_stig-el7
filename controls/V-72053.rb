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

control "V-72053" do
  title "If the cron.allow file exists it must be owned by root."
  desc  "If the owner of the \"cron.allow\" file is not set to root, the possibility
exists for an unauthorized user to view or to edit sensitive information."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72053"
  tag "rid": "SV-86677r1_rule"
  tag "stig_id": "RHEL-07-021110"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that the \"cron.allow\" file is owned by root.

Check the owner of the \"cron.allow\" file with the following command:

# l s -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the \"cron.allow\" file exists and has an owner other than root, this is a
finding."
  tag "fix": "Set the owner on the \"/etc/cron.allow\" file to root with the
following command:

# chown root /etc/cron.allow"

  describe.one do
    # case where file doesn't exist
    describe file('/etc/cron.allow') do
      it { should_not exist }
    end
    # case where file exists
    describe file('/etc/cron.allow') do
      it { should be_owned_by 'root' }
    end
  end
end
