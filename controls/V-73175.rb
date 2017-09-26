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

control "V-73175" do
  title "The system must ignore Internet Protocol version 4 (IPv4) Internet Control
Message Protocol (ICMP) redirect messages."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the host's
route table and are unauthenticated. An illicit ICMP redirect message could result
in a man-in-the-middle attack."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73175"
  tag "rid": "SV-87827r2_rule"
  tag "stig_id": "RHEL-07-040641"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "networking","kernel"
  tag "check": "Verify the system ignores IPv4 ICMP redirect messages.

Check the value of the \"accept_redirects\" variables with the following command:

# /sbin/sysctl -a | grep  'net.ipv4.conf.all.accept_redirects'

net.ipv4.conf.all.accept_redirects=0

If both of the returned lines do not have a value of \"0\", or a line is not
returned, this is a finding."

  tag "fix": "Set the system to ignore IPv4 ICMP redirect messages by adding the
following line to \"/etc/sysctl.conf\" (or modify the line to have the required
value): net.ipv4.conf.all.accept_redirects = 0"

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
end
