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

control "V-71949" do
  title "Users must re-authenticate for privilege escalation."
  desc  "
    Without re-authentication, users may access resources or perform tasks for which
they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157,
SRG-OS-000373-GPOS-0015.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000373-GPOS-00156"
  tag "gid": "V-71949"
  tag "rid": "SV-86573r2_rule"
  tag "stig_id": "RHEL-07-010350"
  tag "cci": "CCI-002038"
  tag "nist": ["IA-11", "Rev_4"]
  tag "check": "Verify the operating system requires users to reauthenticate for
privilege escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files with
the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any line is found with a \"!authenticate\" tag, this is a finding."
  tag "fix": "Configure the operating system to require users to reauthenticate for
privilege escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files with
the following command:

Remove any occurrences of \"!authenticate\" tags in the file."

  describe command("grep -i authenticate /etc/sudoers /etc/sudoers.d/*") do
    its('stdout') { should_not match /!authenticate/ }
  end
end
