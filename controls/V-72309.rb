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

# @todo add logic for an attribute for being a router

control "V-72309" do
  title "The system must not be performing packet forwarding unless the system is a
router."
  desc  "Routing protocol daemons are typically used on routers to exchange network
topology information with other routers. If this software is used when not required,
system network information may be unnecessarily transmitted across the network."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72309"
  tag "rid": "SV-86933r1_rule"
  tag "stig_id": "RHEL-07-040740"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the system is not performing packet forwarding, unless the
system is a router.

Check to see if IP forwarding is enabled using the following command:

# /sbin/sysctl -a | grep  net.ipv4.ip_forward
net.ipv4.ip_forward=0

If IP forwarding value is \"1\" and the system is hosting any application, database,
or web servers, this is a finding."

  tag "fix": "Set the system to the required kernel parameter by adding the
following line to \"/etc/sysctl.conf\" (or modify the line to have the required
value):

net.ipv4.ip_forward = 0"

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end

end
