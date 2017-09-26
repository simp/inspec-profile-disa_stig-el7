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

control "V-71929" do
  title "Passwords for new users must be restricted to a 60-day maximum lifetime."
  desc  "Any password, no matter how complex, can eventually be cracked. Therefore,
passwords need to be changed periodically. If the operating system does not limit
the lifetime of passwords and force users to change their passwords, there is the
risk that the operating system passwords could be compromised."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-71929"
  tag "rid": "SV-86553r1_rule"
  tag "stig_id": "RHEL-07-010250"
  tag "cci": "CCI-000199"
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "check": "Verify the operating system enforces a 60-day maximum password
lifetime restriction for new user accounts.

Check for the value of \"PASS_MAX_DAYS\" in \"/etc/login.defs\" with the following
command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS     60

If the \"PASS_MAX_DAYS\" parameter value is not 60 or less, or is commented out,
this is a finding."
  tag "fix": "Configure the operating system to enforce a 60-day maximum password
lifetime restriction.

Add the following line in \"/etc/login.defs\" (or modify the line to have the
required value):

PASS_MAX_DAYS     60"

  describe login_defs do
    its('PASS_MAX_DAYS.to_i') { should cmp <= 60 }
  end
end
