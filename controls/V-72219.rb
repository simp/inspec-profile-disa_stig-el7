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

# TODO we need to write tests on this.

control "V-72219" do
  title "The host must be configured to prohibit or restrict the use of functions,
ports, protocols, and/or services, as defined in the Ports, Protocols, and Services
Management Component Local Service Assessment (PPSM CLSA) and vulnerability
assessments."
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized transfer of
information, or unauthorized tunneling (i.e., embedding of data types within data
types), organizations must disable or restrict unused or unnecessary physical and
logical ports/protocols on information systems.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component (e.g., VPN
and IPS); however, doing so increases risk over limiting the services provided by
any one component.

    To support the requirements and principles of least functionality, the operating
system must support the organizational requirements, providing only essential
capabilities and limiting the use of ports, protocols, and/or services to only those
required, authorized, and approved to conduct official business or to address
authorized quality of life issues.

    Satisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000297-GPOS-0011.
  "
  impact 0.5

  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-72219"
  tag "rid": "SV-86843r1_rule"
  tag "stig_id": "RHEL-07-040100"
  tag "cci": ["CCI-000382","CCI-002314"]
  tag "nist": ["CM-7 b","AC-17 (1)","Rev_4"]
  tag "check": "Inspect the firewall configuration and running services to verify
that it is configured to prohibit or restrict the use of functions, ports,
protocols, and/or services that are unnecessary or prohibited.

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

Ask the System Administrator for the site or program PPSM CLSA. Verify the services
allowed by the firewall match the PPSM CLSA.

If there are additional ports, protocols, or services that are not in the PPSM CLSA,
or there are ports, protocols, or services that are prohibited by the PPSM Category
Assurance List (CAL), this is a finding."
  tag "fix": "Update the host's firewall settings and/or running services to comply
with the PPSM CLSA for the site or program and the PPSM CAL."

  describe "This test currently has no automated tests, you must check manually" do
    skip "This check must be preformed manually"
  end
end
