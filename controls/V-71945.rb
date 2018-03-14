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

control "V-71945" do
  title "If three unsuccessful root logon attempts within 15 minutes occur the
associated account must be locked."
  desc  "
    By limiting the number of failed logon attempts, the risk of unauthorized system
access via user password guessing, otherwise known as brute-forcing, is reduced.
Limits are imposed by locking the account.

    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-0000.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "gid": "V-71945"
  tag "rid": "SV-86569r1_rule"
  tag "stig_id": "RHEL-07-010330"
  tag "cci": "CCI-002238"
  tag "nist": ["AC-7 b", "Rev_4"]
  tag "subsystems": ['pam']
  tag "check": "Verify the operating system automatically locks the root account
until it is released by an administrator when three unsuccessful logon attempts in
15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth-ac
auth        required       pam_faillock.so preauth silent audit deny=3
even_deny_root fail_interval=900
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root
fail_interval=900

If the \"even_deny_root\" setting is not defined on both lines with the
\"pam_faillock.so\" module name, this is a finding."
  tag "fix": "Configure the operating system to automatically lock the root account
until the locked account is released by an administrator when three unsuccessful
logon attempts in 15 minutes are made.

Modify the first three lines of the auth section of the
\"/etc/pam.d/system-auth-ac\" and \"/etc/pam.d/password-auth-ac\" files to match the
following lines:

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800
auth        sufficient     pam_unix.so try_first_pass
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root
fail_interval=900 unlock_time=604800

and run the \"authconfig\" command."

  files = ["/etc/pam.d/system-auth-ac","/etc/pam.d/password-auth-ac"]
  files.each do |config_file|
    describe file(config_file) do
      its('content') { should match /auth\s+required\s+pam_faillock.so preauth silent audit deny=\d+ even_deny_root fail_interval=\d+ unlock_time=\d+/ }
    end
    describe file(config_file) do
      its('content') { should match /auth\s+\[default=die\]\s+pam_faillock.so authfail audit deny=\d+ even_deny_root fail_interval=\d+ unlock_time=\d+/ }
    end
  end
end
