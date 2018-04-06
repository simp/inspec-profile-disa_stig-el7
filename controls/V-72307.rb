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

# TODO this needs to be reworked to allow `X11_NEEDED` attribute

X11_ENABLED = attribute(
  'x11_enabled',
  description: 'Set to `true` if a GUI or X11 is needed on the system',
  default: false
)

control "V-72307" do
  title "An X Windows display manager must not be installed unless approved."
  desc  "Internet services that are not required for system or application processes
must not be active to decrease the attack surface of the system. X Windows has a
long history of security vulnerabilities and will not be used unless approved and
documented."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72307"
  tag "rid": "SV-86931r2_rule"
  tag "stig_id": "RHEL-07-040730"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that if the system has X Windows System installed, it is
authorized.

Check for the X11 package with the following command:

# yum group list installed \"X Window System\"

Ask the System Administrator if use of the X Windows System is an operational
requirement.

If the use of X Windows on the system is not documented with the Information System
Security Officer (ISSO), this is a finding."
  tag "fix": "Document the requirement for an X Windows server with the ISSO or
remove the related packages with the following commands:

#yum groupremove \"X Window System\"

#yum remove xorg-x11-server-common"

  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end if !X11_ENABLED

  describe package('xorg-x11-server-common') do
    it { should be_installed }
  end if X11_ENABLED
end
