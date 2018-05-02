# encoding: utf-8
#

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
tunneling is required, it must be documented with the Information System
Security Officer (ISSO)."
if !package('libreswan').installed? || !service('ipsec.service').running?
  impact 0.0
else
  impact 0.5
end
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72317"
  tag "rid": "SV-86941r1_rule"
  tag "stig_id": "RHEL-07-040820"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the system does not have unauthorized IP tunnels
configured.

Check to see if \"libreswan\" is installed with the following command:

# yum list installed libreswan
openswan-2.6.32-27.el6.x86_64

If \"libreswan\" is installed, check to see if the \"IPsec\" service is active
with the following command:

# systemctl status ipsec
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
   Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
   Active: inactive (dead)

If the \"IPsec\" service is active, check to see if any tunnels are configured
in \"/etc/ipsec.conf\" and \"/etc/ipsec.d/\" with the following commands:

# grep -i conn /etc/ipsec.conf
conn mytunnel

# grep -i conn /etc/ipsec.d/*.conf
conn mytunnel

If there are indications that a \"conn\" parameter is configured for a tunnel,
ask the System Administrator if the tunnel is documented with the ISSO. If
\"libreswan\" is installed, \"IPsec\" is active, and an undocumented tunnel is
active, this is a finding."
  tag "fix": "Remove all unapproved tunnels from the system, or document them
with the ISSO."
  tag "fix_id": "F-78671r1_fix"

    @grep_ipsec_conf = inspec.command("grep -i conn /etc/ipsec.conf").stdout.split("\n")
    @grep_ipsec_d = inspec.command("grep -i conn /etc/ipsec.d/*.conf").stdout.split("\n")

    @conn_grep_results = @grep_ipsec_conf + @grep_ipsec_d
    @conn_grep_results.each do |curr_line|
        describe curr_line do
          it { should be_in tunnels }
        end
    end if package('libreswan').installed? && service('ipsec.service').running?

  describe "The system does not have openswan installed or the ipsec.service isn't running" do
    skip "The system does not have openswan installed or the ipsec.service isn't running, this requirement is Not Applicable."
  end if !package('libreswan').installed? || !service('ipsec.service').running?

end
