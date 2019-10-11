# encoding: utf-8
#
control "V-72293" do
  title "The system must not send Internet Protocol version 4 (IPv4) Internet
Control Message Protocol (ICMP) redirects."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages contain
information from the system's route table, possibly revealing portions of the
network topology."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72293"
  tag "rid": "SV-86917r2_rule"
  tag "stig_id": "RHEL-07-040660"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['kernel_parameter']
  desc "check", "Verify the system does not send IPv4 ICMP redirect messages.

Check the value of the \"all send_redirects\" variables with the following
command:

# grep  'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf

net.ipv4.conf.all.send_redirects=0

If the returned line does not have a value of \"0\", or a line is not returned,
this is a finding."
  desc "fix", "Configure the system to not allow interfaces to perform IPv4 ICMP
redirects.

Set the system to the required kernel parameter by adding the following line to
\"/etc/sysctl.conf\" (or modify the line to have the required value):

net.ipv4.conf.all.send_redirects=0"
  tag "fix_id": "F-78647r2_fix"

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
end
