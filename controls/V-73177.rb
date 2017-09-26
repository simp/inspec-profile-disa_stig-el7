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

control "V-73177" do
  title "Wireless network adapters must be disabled."
  desc "The use of wireless networking can introduce many different attack vectors
    into the organization's network. Common attack vectors such as malicious
    association and ad hoc networks will allow an attacker to spoof a wireless
    access point (AP), allowing validated systems to connect to the malicious AP
    and enabling the attacker to monitor and record network traffic. These
    malicious APs can also serve to create a man-in-the-middle attack or be used
    to create a denial of service to valid network resources."
  impact 0.5
  tag "severity": "medium"

  tag "gtitle": "SRG-OS-000424-GPOS-00188"
  tag "gid": "V-73177"
  tag "rid": "SV-87829r1_rule"
  tag "stig_id": "RHEL-07-041010"
  tag "cci": "CCI-001443"
  tag "nist": ["AC-18 (1)", "Rev_4"]
  tag "cci": "CCI-001444"
  tag "nist": ["AC-18 (1)", "Rev_4"]
  tag "cci": "CCI-002418"
  tag "nist": ["SC-8", "Rev_4"]
  tag "networking","wifi"

  tag "check":
    "Verify that there are no wireless interfaces configured on the system.

    This is N/A for systems that do not have wireless network adapters.

    Check for the presence of active wireless interfaces with the following command:

    # nmcli device
    DEVICE TYPE STATE
    eth0 ethernet connected
    wlp3s0 wifi disconnected
    lo loopback unmanaged

    If a wireless interface is configured and its use on the system is not
    documented with the Information System Security Officer (ISSO), this is a
    finding."

  tag "fix":
    "Configure the system to disable all wireless network interfaces
    with the following command:

    # nmcli radio wifi off"

    describe command('nmcli device') do
      its('stdout.strip') { should_not match /wifi connected/ }
    end
end
