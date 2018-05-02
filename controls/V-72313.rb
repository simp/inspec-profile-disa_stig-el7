# encoding: utf-8
#
control "V-72313" do
  title "SNMP community strings must be changed from the default."
  desc  "Whether active or not, default Simple Network Management Protocol
(SNMP) community strings must be changed to maintain security. If the service
is running with the default authenticators, anyone can gather data about the
system and the network and use the information to potentially compromise the
integrity of the system or network(s). It is highly recommended that SNMP
version 3 user authentication and message encryption be used in place of the
version 2 community strings."
if file('/etc/snmp/snmpd.conf').exist?
  impact 0.7
else
  impact 0.0
end
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72313"
  tag "rid": "SV-86937r1_rule"
  tag "stig_id": "RHEL-07-040800"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that a system using SNMP is not using default community
strings.

Check to see if the \"/etc/snmp/snmpd.conf\" file exists with the following
command:

# ls -al /etc/snmp/snmpd.conf
 -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf

If the file does not exist, this is Not Applicable.

If the file does exist, check for the default community strings with the
following commands:

# grep public /etc/snmp/snmpd.conf
# grep private /etc/snmp/snmpd.conf

If either of these commands returns any output, this is a finding."
  tag "fix": "If the \"/etc/snmp/snmpd.conf\" file exists, modify any lines
that contain a community string value of \"public\" or \"private\" to another
string value."
  tag "fix_id": "F-78667r1_fix"

  describe file('/etc/snmp/snmpd.conf') do
    its('content') { should_not match %r{public|private} }
  end if file('/etc/snmp/snmpd.conf').exist?

  describe "The `snmpd.conf` does not exist" do
    skip "The snmpd.conf file does not exist, this control is Not Applicable"
  end if !file('/etc/snmp/snmpd.conf').exist?
end
