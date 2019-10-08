# encoding: utf-8
#
control "V-72053" do
  title "If the cron.allow file exists it must be owned by root."
  desc  "If the owner of the \"cron.allow\" file is not set to root, the
possibility exists for an unauthorized user to view or to edit sensitive
information."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72053"
  tag "rid": "SV-86677r2_rule"
  tag "stig_id": "RHEL-07-021110"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['cron']
  desc "check", "Verify that the \"cron.allow\" file is owned by root.

Check the owner of the \"cron.allow\" file with the following command:

# ls -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the \"cron.allow\" file exists and has an owner other than root, this is a
finding."
  desc "fix", "Set the owner on the \"/etc/cron.allow\" file to root with the
following command:

# chown root /etc/cron.allow"
  tag "fix_id": "F-78405r1_fix"

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
