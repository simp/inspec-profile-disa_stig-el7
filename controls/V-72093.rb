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

control "V-72093" do
  title "The operating system must immediately notify the System Administrator (SA)
and Information System Security Officer (ISSO) (at a minimum) when the threshold for
the repository maximum audit record storage capacity is reached."
  desc  "If security personnel are not notified immediately when the threshold for
the repository maximum audit record storage capacity is reached, they are unable to
expand the audit record storage capacity before records are lost."
  impact 0.5

  tag "gtitle": "SRG-OS-000343-GPOS-00134"
  tag "gid": "V-72093"
  tag "rid": "SV-86717r2_rule"
  tag "stig_id": "RHEL-07-030350"
  tag "cci": "CCI-001855"
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd']
  tag "check": "Verify the operating system immediately notifies the SA and ISSO (at
a minimum) via email when the threshold for the repository maximum audit record
storage capacity is reached.

Check what account the operating system emails when the threshold for the repository
maximum audit record storage capacity is reached with the following command:

# grep -i action_mail_acct  /etc/audit/auditd.conf
action_mail_acct = root

If the value of the \"action_mail_acct\" keyword is not set to \"root\" and other
accounts for security personnel, this is a finding."
  tag "fix": "Configure the operating system to immediately notify the SA and ISSO
(at a minimum) when the threshold for the repository maximum audit record storage
capacity is reached.

Uncomment or edit the \"action_mail_acct\" keyword in \"/etc/audit/auditd.conf\" and
set it to root and any other accounts associated with security personnel.

action_mail_acct = root"

  describe auditd_conf  do
    its('action_mail_acct') { should cmp 'root' }
  end
end
