control 'SV-204612' do
  title 'The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4)
    source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a
    different path than configured on the router, which can be used to bypass network security measures. This
    requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the
    system is functioning as a router.'
  tag 'legacy': ['V-72285', 'SV-86909']
  tag 'rationale': ''
  tag 'check': 'Verify the system does not accept IPv4 source-routed packets by default.
    # grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf /etc/sysctl.d/*
    net.ipv4.conf.default.accept_source_route = 0
    If " net.ipv4.conf.default.accept_source_route " is not configured in the /etc/sysctl.conf file or in the
    /etc/sysctl.d/ directory, is commented out, or does not have a value of "0", this is a finding.
    Check that the operating system implements the accept source route variable with the following command:
    # /sbin/sysctl -a | grep net.ipv4.conf.default.accept_source_route
    net.ipv4.conf.default.accept_source_route = 0
    If the returned line does not have a value of "0", this is a finding.'
  tag 'fix': 'Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or
    a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):
    net.ipv4.conf.default.accept_source_route = 0
    Issue the following command to make the changes take effect:
    # sysctl --system'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204612'
  tag 'rid': 'SV-204612r603261_rule'
  tag 'stig_id': 'RHEL-07-040620'
  tag 'fix_id': 'F-4736r89029_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
end
