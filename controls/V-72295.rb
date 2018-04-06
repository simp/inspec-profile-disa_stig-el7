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

control "V-72295" do
  title "Network interfaces must not be in promiscuous mode."
  desc  "
    Network interfaces in promiscuous mode allow for the capture of all network
traffic visible to the system. If unauthorized individuals can access these
applications, it may allow then to collect information such as logon IDs, passwords,
and key exchanges between systems.

    If the system is being used to perform a network troubleshooting function, the
use of these tools must be documented with the Information System Security Officer
(ISSO) and restricted to only authorized personnel.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72295"
  tag "rid": "SV-86919r1_rule"
  tag "stig_id": "RHEL-07-040670"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify network interfaces are not in promiscuous mode unless
approved by the ISSO and documented.

Check for the status with the following command:

# ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has
not been approved by the ISSO and documented, this is a finding."
  tag "fix": "Configure network interfaces to turn off promiscuous mode unless
approved by the ISSO and documented.

Set the promiscuous mode of an interface to off with the following command:

#ip link set dev <devicename> multicast off promisc off"

  # @todo - test against list of approved interfaces
  describe command("ip link | grep -i promisc") do
    its('stdout.strip') { should match %r{^$} }
  end
end
