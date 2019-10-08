# encoding: utf-8
#

# TODO we need to write tests on this.

control "V-72219" do
  title "The host must be configured to prohibit or restrict the use of
functions, ports, protocols, and/or services, as defined in the Ports,
Protocols, and Services Management Component Local Service Assessment (PPSM
CLSA) and vulnerability assessments."
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized
transfer of information, or unauthorized tunneling (i.e., embedding of data
types within data types), organizations must disable or restrict unused or
unnecessary physical and logical ports/protocols on information systems.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., VPN and IPS); however, doing so increases risk over limiting the
services provided by any one component.

    To support the requirements and principles of least functionality, the
operating system must support the organizational requirements, providing only
essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality of life issues.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "satisfies": ["SRG-OS-000096-GPOS-00050", "SRG-OS-000297-GPOS-00115"]
  tag "gid": "V-72219"
  tag "rid": "SV-86843r1_rule"
  tag "stig_id": "RHEL-07-040100"
  tag "cci": ["CCI-000382", "CCI-002314"]
  tag "documentable": false
  tag "nist": ["CM-7 b", "AC-17 (1)", "Rev_4"]
  tag "subsystems": ['firewall', 'manual']
  desc "check", "Inspect the firewall configuration and running services to
verify that it is configured to prohibit or restrict the use of functions,
ports, protocols, and/or services that are unnecessary or prohibited.

Check which services are currently active with the following command:

# firewall-cmd --list-all
public (default, active)
  interfaces: enp0s3
  sources:
  services: dhcpv6-client dns http https ldaps rpc-bind ssh
  ports:
  masquerade: no
  forward-ports:
  icmp-blocks:
  rich rules:

Ask the System Administrator for the site or program PPSM CLSA. Verify the
services allowed by the firewall match the PPSM CLSA.

If there are additional ports, protocols, or services that are not in the PPSM
CLSA, or there are ports, protocols, or services that are prohibited by the
PPSM Category Assurance List (CAL), this is a finding."
  desc "fix", "Update the host's firewall settings and/or running services to
comply with the PPSM CLSA for the site or program and the PPSM CAL."
  tag "fix_id": "F-78573r1_fix"

  describe "This test currently has no automated tests, you must check manually" do
    skip "This check must be preformed manually"
  end
end
