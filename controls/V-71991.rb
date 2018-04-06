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

control "V-71991" do
  title "The operating system must enable the SELinux targeted policy."
  desc  "
    Without verification of the security functions, security functions may not
operate correctly and the failure may go unnoticed. Security function is defined as
the hardware, software, and/or firmware of the information system responsible for
enforcing the system security policy and supporting the isolation of code and data
on which the protection is based. Security functionality includes, but is not
limited to, establishing system accounts, configuring access authorizations (i.e.,
permissions, privileges), setting events to be audited, and setting intrusion
detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this functionality.
  "
  impact 0.7

  tag "gtitle": "SRG-OS-000445-GPOS-00199"
  tag "gid": "V-71991"
  tag "rid": "SV-86615r2_rule"
  tag "stig_id": "RHEL-07-020220"
  tag "cci": ["CCI-002165","CCI-002696"]
  tag "nist": ["AC-3 (4)","SI-6 a","Rev_4"]
  tag "subsystems": ['selinux']
  tag "check": "Verify the operating system verifies correct operation of all
security functions.

Check if \"SELinux\" is active and is enforcing the targeted policy with the
following command:

# sestatus
SELinux status:                 enabled
SELinuxfs mount:                /selinu
XCurrent mode:                   enforcing
Mode from config file:          enforcing
Policy version:                 24
Policy from config file:        targeted

If the \"Policy from config file\" is not set to \"targeted\", or the \"Loaded
policy name\" is not set to \"targeted\", this is a finding."
  tag "fix": "Configure the operating system to verify correct operation of all
security functions.

Set the \"SELinuxtype\" to the \"targeted\" policy by modifying the
\"/etc/selinux/config\" file to have the following line:

SELINUXTYPE=targeted

A reboot is required for the changes to take effect."

  #@todo - SELinux resource?? (https://github.com/chef/inspec/issues/534)
  describe.one do
    describe command('sestatus') do
      its('stdout') { should match %r{^Policy\sfrom\sconfigs\sfile:\s+targeted\n?$} }
    end
    describe command('sestatus') do
      its('stdout') { should match %r{^Loaded\spolicy\sname:\s+targeted\n?$} }
    end
  end
end
