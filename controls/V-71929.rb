# encoding: utf-8
#

#TODO Make me an attribute - as part of the PAM_FAMILY / PASSWORD Family attribs

control "V-71929" do
  title "Passwords for new users must be restricted to a 60-day maximum
lifetime."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the operating system
does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the operating system passwords could be
compromised."
  impact 0.5
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-71929"
  tag "rid": "SV-86553r1_rule"
  tag "stig_id": "RHEL-07-010250"
  tag "cci": ["CCI-000199"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "subsystems": ['login_defs', 'password']
  desc "check", "Verify the operating system enforces a 60-day maximum password
lifetime restriction for new user accounts.

Check for the value of \"PASS_MAX_DAYS\" in \"/etc/login.defs\" with the
following command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS     60

If the \"PASS_MAX_DAYS\" parameter value is not 60 or less, or is commented
out, this is a finding."
  desc "fix", "Configure the operating system to enforce a 60-day maximum
password lifetime restriction.

Add the following line in \"/etc/login.defs\" (or modify the line to have the
required value):

PASS_MAX_DAYS     60"
  tag "fix_id": "F-78281r1_fix"
  describe login_defs do
    its('PASS_MAX_DAYS.to_i') { should cmp <= 60 }
  end
end
