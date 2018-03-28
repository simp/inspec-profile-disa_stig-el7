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

control "V-72319" do
  title "The system must not forward IPv6 source-routed packets."
  desc  "Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the router,
which can be used to bypass network security measures. This requirement applies only
to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled
and the system is functioning as a router."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72319"
  tag "rid": "SV-86943r1_rule"
  tag "stig_id": "RHEL-07-040830"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "networking","kernel"
  tag "check": "Verify the system does not accept IPv6 source-routed packets.

Note: If IPv6 is not enabled, the key will not exist, and this is not a finding.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route=0

If the returned lines do not have a value of \"0\", or a line is not returned, this
is a finding."
  tag "fix": "Set the system to the required kernel parameter, if IPv6 is enabled,
by adding the following line to \"/etc/sysctl.conf\" (or modify the line to have the
required value):

net.ipv6.conf.all.accept_source_route = 0"

  describe.one do
    describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
      its('value') { should eq 0 }
    end
	# If IPv6 is disabled in the kernel it will return NIL
    describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
      its('value') { should eq nil }
    end
  end
end
