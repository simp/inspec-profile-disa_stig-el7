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

control "V-71997" do
  title "The operating system must be a vendor supported release."
  desc  "An operating system release is considered \"supported\" if the vendor
continues to provide security patches for the product. With an unsupported release,
it will not be possible to resolve security issues discovered in the system
software."
  impact 0.7

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-71997"
  tag "rid": "SV-86621r2_rule"
  tag "stig_id": "RHEL-07-020250"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 7.2 (Maipo)

Current End of Life for RHEL 7.2 is Q4 2020.

Current End of Life for RHEL 7.3 is 30 June 2024.

If the release is not supported by the vendor, this is a finding."
  tag "fix": "Upgrade to a supported version of the operating system."

  # TODO use an array attribute of supported DISTROS and use the be_in matcher?
  describe file('/etc/redhat-release') do
    its('content') { should match %r{Release (6.7*|7.[2-9].*)}i }
  end
end
