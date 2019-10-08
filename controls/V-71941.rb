# encoding: utf-8
#

days_of_inactivity = input('days_of_inactivity', value: 0, description: 'The
number of days of inactivity before an account is disabled.')

control "V-71941" do
  title "The operating system must disable account identifiers (individuals,
groups, roles, and devices) if the password expires."
  desc  "
    Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Operating systems need to track periods of inactivity and disable
application identifiers after zero days of inactivity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000118-GPOS-00060"
  tag "gid": "V-71941"
  tag "rid": "SV-86565r1_rule"
  tag "stig_id": "RHEL-07-010310"
  tag "cci": ["CCI-000795"]
  tag "documentable": false
  tag "nist": ["IA-4 e", "Rev_4"]
  tag "subsystems": ['user']
  desc "check", "Verify the operating system disables account identifiers
(individuals, groups, roles, and devices) after the password expires with the
following command:

# grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to \"0\", is commented out, or is not defined, this is
a finding."
  desc "fix", "Configure the operating system to disable account identifiers
(individuals, groups, roles, and devices) after the password expires.

Add the following line to \"/etc/default/useradd\" (or modify the line to have
the required value):

INACTIVE=0"
  tag "fix_id": "F-78293r1_fix"
  describe parse_config_file("/etc/default/useradd") do
    its('INACTIVE') { should cmp >= 0 }
    its('INACTIVE') { should cmp <= days_of_inactivity }
  end
end
