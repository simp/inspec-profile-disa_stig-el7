# encoding: utf-8
#
control "V-71947" do
  title "Users must provide a password for privilege escalation."
  desc  "
    Without re-authentication, users may access resources or perform tasks for
which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user re-authenticate.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000373-GPOS-00156"
  tag "satisfies": ["SRG-OS-000373-GPOS-00156", "SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00158"]
  tag "gid": "V-71947"
  tag "rid": "SV-86571r2_rule"
  tag "stig_id": "RHEL-07-010340"
  tag "cci": ["CCI-002038"]
  tag "documentable": false
  tag "nist": ["IA-11", "Rev_4"]
  tag "check": "If passwords are not being used for authentication, this is Not
Applicable.

Verify the operating system requires users to supply a password for privilege
escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files
with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any uncommented line is found with a \"NOPASSWD\" tag, this is a finding."
  tag "fix": "Configure the operating system to require users to supply a
password for privilege escalation.

Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files
with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

Remove any occurrences of \"NOPASSWD\" tags in the file."
  tag "fix_id": "F-78299r1_fix"
  # @todo update logic in case of multiple NOPASSWD findings
  describe.one do
    # case where NOPASSWD line is commented out
    describe command("grep -ir nopasswd /etc/sudoers /etc/sudoers.d/*") do
      its('stdout') { should match %r{.*#.*NOPASSWD} }
    end
    # case where NOPASSWD is found in uncommented line
    describe command("grep -ir nopasswd /etc/sudoers /etc/sudoers.d/*") do
      its('stdout') { should_not match %r{NOPASSWD} }
    end
  end
end
