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

control "V-72085" do
  title "The operating system must encrypt the transfer of audit records off-loaded
onto a different system or media from the system being audited."
  desc  "
    Information stored in one location is vulnerable to accidental or incidental
deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-0022.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "gid": "V-72085"
  tag "rid": "SV-86709r1_rule"
  tag "stig_id": "RHEL-07-030310"
  tag "cci": "CCI-001851"
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audisp']
  tag "check": "Verify the operating system encrypts audit records off-loaded onto a
different system or media from the system being audited.

To determine if the transfer is encrypted, use the following command:

# grep -i enable_krb5 /etc/audisp/audisp-remote.conf
enable_krb5 = yes

If the value of the \"enable_krb5\" option is not set to \"yes\" or the line is
commented out, ask the System Administrator to indicate how the audit logs are
off-loaded to a different system or media.

If there is no evidence that the transfer of the audit logs being off-loaded to
another system or media is encrypted, this is a finding."
  tag "fix": "Configure the operating system to encrypt the transfer of off-loaded
audit records onto a different system or media from the system being audited.

Uncomment the \"enable_krb5\" option in \"/etc/audisp/audisp-remote.conf\" and set
it with the following line:

enable_krb5 = yes"

  describe parse_config_file('/etc/audisp/audisp-remote.conf') do
    its('enable_krb5.strip') { should cmp('yes') }
  end
end
