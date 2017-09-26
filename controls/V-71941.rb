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

control "V-71941" do
  title "The operating system must disable account identifiers (individuals, groups,
roles, and devices) if the password expires."
  desc  "
    Inactive identifiers pose a risk to systems and applications because attackers
may exploit an inactive identifier and potentially obtain undetected access to the
system. Owners of inactive accounts will not notice if unauthorized access to their
user account has been obtained.

    Operating systems need to track periods of inactivity and disable application
identifiers after zero days of inactivity.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000118-GPOS-00060"
  tag "gid": "V-71941"
  tag "rid": "SV-86565r1_rule"
  tag "stig_id": "RHEL-07-010310"
  tag "cci": "CCI-000795"
  tag "nist": ["IA-4 e", "Rev_4"]
  tag "check": "Verify the operating system disables account identifiers
(individuals, groups, roles, and devices) after the password expires with the
following command:

# grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to \"0\", is commented out, or is not defined, this is a
finding."
  tag "fix": "Configure the operating system to disable account identifiers
(individuals, groups, roles, and devices) after the password expires.

Add the following line to \"/etc/default/useradd\" (or modify the line to have the
required value):

INACTIVE=0"

  describe parse_config_file("/etc/default/useradd") do
    its('INACTIVE') { should cmp '0' }
  end
end
