control 'SV-204611' do
  title 'The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when
    possible by default.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be
    received on the interface they were received on. It should not be used on systems which are routers for complicated
    networks, but is helpful for end hosts and routers serving small networks.'
  desc 'rationale', ''
  desc 'check', 'Verify the system uses a reverse-path filter for IPv4:
    # grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/*
    net.ipv4.conf.default.rp_filter = 1
    If "net.ipv4.conf.default.rp_filter" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/
    directory, is commented out, or does not have a value of "1", this is a finding.
    Check that the operating system implements the accept source route variable with the following command:
    # /sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter
    net.ipv4.conf.default.rp_filter = 1
    If the returned line does not have a value of "1", this is a finding.'
  desc  'fix', "
    Set the system to the required kernel parameter by adding the following
line to \"/etc/sysctl.conf\" or a configuration file in the /etc/sysctl.d/
directory (or modify the line to have the required value):

    net.ipv4.conf.default.rp_filter = 1

    Issue the following command to make the changes take effect:

    # sysctl --system
  "
  impact 0.5
  tag 'legacy': ['V-92253', 'SV-102355']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204611'
  tag 'rid': 'SV-204611r603261_rule'
  tag 'stig_id': 'RHEL-07-040612'
  tag 'fix_id': 'F-4735r89026_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['kernel_parameter', 'ipv4']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - Kernel config must be done on the host' do
      skip 'Control not applicable - Kernel config must be done on the host'
    end
  else
    describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
      its('value') { should eq 1 }
    end
  end
end
