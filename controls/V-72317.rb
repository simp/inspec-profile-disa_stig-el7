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

tunnels = attribute(
  'tunnels',
  default: [
    # Example
    # 'conn myTunnel'
  ],
  description: "Approved configured tunnels prepended with word 'conn'"
)

control "V-72317" do
  title "The system must not have unauthorized IP tunnels configured."
  desc  "IP tunneling mechanisms can be used to bypass network filtering. If
tunneling is required, it must be documented with the Information System Security
Officer (ISSO)."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72317"
  tag "rid": "SV-86941r1_rule"
  tag "stig_id": "RHEL-07-040820"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the system does not have unauthorized IP tunnels configured.

Check to see if \"libreswan\" is installed with the following command:

# yum list installed libreswan
openswan-2.6.32-27.el6.x86_64

If \"libreswan\" is installed, check to see if the \"IPsec\" service is active with
the following command:

# systemctl status ipsec
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
   Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
   Active: inactive (dead)

If the \"IPsec\" service is active, check to see if any tunnels are configured in
\"/etc/ipsec.conf\" and \"/etc/ipsec.d/\" with the following commands:

# grep -i conn /etc/ipsec.conf
conn mytunnel

# grep -i conn /etc/ipsec.d/*.conf
conn mytunnel

If there are indications that a \"conn\" parameter is configured for a tunnel, ask
the System Administrator if the tunnel is documented with the ISSO. If \"libreswan\"
is installed, \"IPsec\" is active, and an undocumented tunnel is active, this is a
finding."
  tag "fix": "Remove all unapproved tunnels from the system, or document them with
the ISSO."

    @conn_grep_results = inspec.command("grep -i issue /etc/audit/audit.rules").stdout.split("\n")

    @conn_grep_results.each do |curr_line|
        describe curr_line do
          it { should be_in tunnels }
        end
    end
    only_if { package('libreswan').installed? }
    only_if { service('ipsec.service').running? }
end
