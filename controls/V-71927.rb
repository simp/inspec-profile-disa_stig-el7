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

control "V-71927" do
  title "Passwords must be restricted to a 24 hours/1 day minimum lifetime."
  desc  "Enforcing a minimum password lifetime helps to prevent repeated password
changes to defeat the password reuse or history enforcement requirement. If users
are allowed to immediately and continually change their password, the password could
be repeatedly changed in a short period of time to defeat the organization's policy
regarding password reuse."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000075-GPOS-00043"
  tag "gid": "V-71927"
  tag "rid": "SV-86551r1_rule"
  tag "stig_id": "RHEL-07-010240"
  tag "cci": "CCI-000198"
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "check": "Check whether the minimum time period between password changes for
each user account is one day or greater.

# awk -F: '$4 < 1 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a
finding."
  tag "fix": "Configure non-compliant accounts to enforce a 24 hours/1 day minimum
password lifetime:

# chage -m 1 [user]"

  shadow.users.each do |user|
    # filtering on non-system accounts (uid >= 1000)
    next unless user(user).uid >= 1000
    # Filtering EC2-USER as this accounts expected to not have an expiring password
    next if user cmp  'ec2-user'
    describe shadow.users(user) do
      its('min_days.first.to_i') { should cmp >= 1 }
    end
  end
end
