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

control "V-71947" do
  title "Users must provide a password for privilege escalation."
  desc  "
    Without re-authentication, users may access resources or perform tasks for which
they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user re-authenticate.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157,
SRG-OS-000373-GPOS-0015.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000373-GPOS-00156"
  tag "gid": "V-71947"
  tag "rid": "SV-86571r1_rule"
  tag "stig_id": "RHEL-07-010340"
  tag "cci": "CCI-002038"
  tag "nist": ["IA-11", "Rev_4"]
  tag "check": "Verify the operating system requires users to supply a password for
privilege escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files with
the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any uncommented line is found with a \"NOPASSWD\" tag, this is a finding."
  tag "fix": "Configure the operating system to require users to supply a password
for privilege escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files with
the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

Remove any occurrences of \"NOPASSWD\" tags in the file."

  # @todo update logic in case of multiple NOPASSWD findings
  describe.one do
    # case where NOPASSWD line is commented out
    describe command("grep -i nopasswd /etc/sudoers /etc/sudoers.d/*") do
      its('stdout') { should match /.*#.*NOPASSWD/ }
    end
    # case where NOPASSWD is found in uncommented line
    describe command("grep -i nopasswd /etc/sudoers /etc/sudoers.d/*") do
      its('stdout') { should_not match /NOPASSWD/ }
    end
  end
end
