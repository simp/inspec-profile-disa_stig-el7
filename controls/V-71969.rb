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

control "V-71969" do
  title "The ypserv package must not be installed."
  desc  "Removing the \"ypserv\" package decreases the risk of the accidental (or
intentional) activation of NIS or NIS+ services."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-71969"
  tag "rid": "SV-86593r1_rule"
  tag "stig_id": "RHEL-07-020010"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "The NIS service provides an unencrypted authentication service that
does not provide for the confidentiality and integrity of user passwords or the
remote session.

Check to see if the \"ypserve\" package is installed with the following command:

# yum list installed ypserv

If the \"ypserv\" package is installed, this is a finding."
  tag "fix": "Configure the operating system to disable non-essential capabilities
by removing the \"ypserv\" package from the system with the following command:

# yum remove ypserv"

  describe package("ypserv") do
    it { should_not be_installed }
  end
end
