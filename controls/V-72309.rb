# encoding: utf-8
#

# @todo add logic for an attribute for being a router

control "V-72309" do
  title "The system must not be performing packet forwarding unless the system
is a router."
  desc  "Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72309"
  tag "rid": "SV-86933r1_rule"
  tag "stig_id": "RHEL-07-040740"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['kernel_parameter']
  desc "check", "Verify the system is not performing packet forwarding, unless
the system is a router.

Check to see if IP forwarding is enabled using the following command:

# /sbin/sysctl -a | grep  net.ipv4.ip_forward
net.ipv4.ip_forward=0

If IP forwarding value is \"1\" and the system is hosting any application,
database, or web servers, this is a finding."
  desc "fix", "Set the system to the required kernel parameter by adding the
following line to \"/etc/sysctl.conf\" (or modify the line to have the required
value):

net.ipv4.ip_forward = 0"
  tag "fix_id": "F-78663r1_fix"

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end

end
