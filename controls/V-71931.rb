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

control "V-71931" do
  title "Existing passwords must be restricted to a 60-day maximum lifetime."
  desc  "Any password, no matter how complex, can eventually be cracked. Therefore,
passwords need to be changed periodically. If the operating system does not limit
the lifetime of passwords and force users to change their passwords, there is the
risk that the operating system passwords could be compromised."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-71931"
  tag "rid": "SV-86555r1_rule"
  tag "stig_id": "RHEL-07-010260"
  tag "cci": "CCI-000199"
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "check": "Check whether the maximum time period for existing passwords is
restricted to 60 days.

# awk -F: '$5 > 60 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a
finding."
  tag "fix": "Configure non-compliant accounts to enforce a 60-day maximum password
lifetime restriction.

# chage -M 60 [user]"

  shadow.users.each do |user|
    # filtering on non-system accounts (uid >= 1000)
    next unless user(user).uid >= 1000
    # Skip ec2-user this user will be set to 99999
    # ec2-user doesn't have a password
    next if user cmp 'ec2-user'
    describe shadow.users(user) do
      its('max_days.first.to_i') { should cmp <= 60 }
    end
  end
end
