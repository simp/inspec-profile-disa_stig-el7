# encoding: utf-8
#

# TODO we need to account for the case when IPV6 is not disabled and check it

control "V-72319" do
  title "The system must not forward IPv6 source-routed packets."
  desc  "Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when IPv6
forwarding is enabled and the system is functioning as a router."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72319"
  tag "rid": "SV-86943r1_rule"
  tag "stig_id": "RHEL-07-040830"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "networking","kernel"
  tag "subsystems": ['kernel_parameter']
  desc "check", "Verify the system does not accept IPv6 source-routed packets.

Note: If IPv6 is not enabled, the key will not exist, and this is not a finding.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route=0

If the returned lines do not have a value of \"0\", or a line is not returned,
this is a finding."
  desc "fix", "Set the system to the required kernel parameter, if IPv6 is
enabled, by adding the following line to \"/etc/sysctl.conf\" (or modify the
line to have the required value):

net.ipv6.conf.all.accept_source_route = 0"
  tag "fix_id": "F-78673r1_fix"

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
