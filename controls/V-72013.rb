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

control "V-72013" do
  title "All local interactive user accounts, upon creation, must be assigned a home
directory."
  desc  "If local interactive users are not assigned a valid home directory, there
is no place for the storage and control of files they should own."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72013"
  tag "rid": "SV-86637r1_rule"
  tag "stig_id": "RHEL-07-020610"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all local interactive users on the system are assigned a home
directory upon creation.

Check to see if the system is configured to create home directories for local
interactive users with the following command:

# grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for \"CREATE_HOME\" parameter is not set to \"yes\", the line is
missing, or the line is commented out, this is a finding."
  tag "fix": "Configure the operating system to assign home directories to all new
local interactive users by setting the \"CREATE_HOME\" parameter in
\"/etc/login.defs\" to \"yes\" as follows.

CREATE_HOME yes"

  describe login_defs do
    its('CREATE_HOME') { should eq 'yes' }
  end
end
