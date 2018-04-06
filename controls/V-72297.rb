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

control "V-72297" do
  title "The system must be configured to prevent unrestricted mail relaying."
  desc  "If unrestricted mail relaying is permitted, unauthorized senders could use
this host as a mail relay for the purpose of sending spam or other unauthorized
activity."
if package('postfix').installed?
  impact 0.5
else
  impact 0.0
end
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72297"
  tag "rid": "SV-86921r2_rule"
  tag "stig_id": "RHEL-07-040680"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the system is configured to prevent unrestricted mail
relaying.

Determine if \"postfix\" is installed with the following commands:

# yum list installed postfix
postfix-2.6.6-6.el7.x86_64.rpm

If postfix is not installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from
unknown or untrusted networks with the following command:

# postconf -n smtpd_client_restrictions
smtpd_client_restrictions = permit_mynetworks, reject

If the \"smtpd_client_restrictions\" parameter contains any entries other than
\"permit_mynetworks\" and \"reject\", this is a finding."
  tag "fix": "If \"postfix\" is installed, modify the \"/etc/postfix/main.cf\" file
to restrict client connections to the local network with the following command:

# postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'"

  # Only permit_mynetworks and reject should be allowed
  describe.one do
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') { should match %r{^smtpd_client_restrictions\s+=\s+permit_mynetworks,\s*reject\s*$} }
    end
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') { should match %r{^smtpd_client_restrictions\s+=\s+permit_mynetworks\s*$} }
    end
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') { should match %r{^smtpd_client_restrictions\s+=\s+reject\s*$} }
    end
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') { should match %r{^smtpd_client_restrictions\s+=\s+reject,\s*permit_mynetworks\s*$} }
    end
  end if package('postfix').installed?

  describe "The `postfix` package is not installed" do
    skip "The `postfix` package is not installed, this control is Not Applicable"
  end if !package('postfix').installed?
end
