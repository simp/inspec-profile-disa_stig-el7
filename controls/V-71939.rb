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

control "V-71939" do
  title "The SSH daemon must not allow authentication using an empty password."
  desc  "Configuring this setting for the SSH daemon provides additional assurance
that remote logon via SSH will require a password, even in the event of
misconfiguration elsewhere."
  impact 0.7

  tag "gtitle": "SRG-OS-000106-GPOS-00053"
  tag "gid": "V-71939"
  tag "rid": "SV-86563r2_rule"
  tag "stig_id": "RHEL-07-010300"
  tag "cci": "CCI-000766"
  tag "nist": ["IA-2 (2)", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "To determine how the SSH daemon's \"PermitEmptyPasswords\" option is
set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config
PermitEmptyPasswords no

If no line, a commented line, or a line indicating the value \"no\" is returned, the
required value is set.

If the required value is not set, this is a finding."
  tag "fix": "To explicitly disallow remote logon from accounts with empty
passwords, add or correct the following line in \"/etc/ssh/sshd_config\":

PermitEmptyPasswords no

The SSH service must be restarted for changes to take effect.  Any accounts with
empty passwords should be disabled immediately, and PAM configuration should prevent
users from being able to assign themselves empty passwords."

  # TODO: We should not allow a nil or unset value - as someday the defualt may change.
  # TODO: Require that user be perscriptive about the state they want - yes or no.

  describe.one do
    # case where value no line is returned ( i.e. unset or commented out )
    describe sshd_config do
      its('PermitEmptyPasswords') { should cmp nil }
    end
    # case where value no is returned
    describe sshd_config do
      its('PermitEmptyPasswords') { should eq 'no' }
    end
  end
end
