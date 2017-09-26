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

control "V-71937" do
  title "The system must not have accounts configured with blank or null passwords."
  desc  "If an account has an empty password, anyone could log on and run commands
with the privileges of that account. Accounts with empty passwords should never be
used in operational environments."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-71937"
  tag "rid": "SV-86561r1_rule"
  tag "stig_id": "RHEL-07-010290"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "To verify that null passwords cannot be used, run the following
command:

# grep nullok /etc/pam.d/system-auth-ac

If this produces any output, it may be possible to log on with accounts with empty
passwords.

If null passwords can be used, this is a finding."
  tag "fix": "If an account is configured for password authentication but does not
have an assigned password, it may be possible to log on to the account without
authenticating.

Remove any instances of the \"nullok\" option in \"/etc/pam.d/system-auth-ac\" to
prevent logons with empty passwords and run the \"authconfig\" command."

  nullok_files = command(%(grep -rle 'pam_unix.so .*nullok' /etc/pam.d/*)).stdout.lines.map(&:strip)

  describe 'PAM authorization files' do
    context nullok_files do
      it { should be_empty }
    end
  end
end
