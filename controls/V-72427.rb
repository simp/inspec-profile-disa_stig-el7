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

control "V-72427" do
  title "The operating system must implement multifactor authentication for access
to privileged accounts via pluggable authentication modules (PAM)."
  desc  "
    Using an authentication device, such as a CAC or token that is separate from the
information system, ensures that even if the information system is compromised, that
compromise will not affect credentials stored on the authentication device.

    Multifactor solutions that require devices separate from information systems
gaining access include, for example, hardware tokens providing time-based or
challenge-response authenticators and smart cards such as the U.S. Government
Personal Identity Verification card and the DoD Common Access Card.

    A privileged account is defined as an information system account with
authorizations of a privileged user.

    Remote access is access to DoD nonpublic information systems by an authorized
user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless.

    This requirement only applies to components where this is specific to the
function of the device or has the concept of an organizational user (e.g., VPN,
proxy capability). This does not apply to authentication for the purpose of
configuring the device itself (management).

    Requires further clarification from NIST.

    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161,
SRG-OS-000375-GPOS-0016.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000375-GPOS-00160"
  tag "gid": "V-72427"
  tag "rid": "SV-87051r2_rule"
  tag "stig_id": "RHEL-07-041002"
  tag "cci": "CCI-001948"
  tag "nist": ["IA-2 (11)", "Rev_4"]
  tag "cci": "CCI-001953"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "cci": "CCI-001954"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "pam","nss","MFA","pki"

  tag "check": "Verify the operating system implements multifactor authentication
for remote access to privileged accounts via pluggable authentication modules (PAM).

Check the \"/etc/sssd/sssd.conf\" file for the authentication services that are
being used with the following command:

# grep services /etc/sssd/sssd.conf

services = nss, pam

If the \"pam\" service is not present, this is a finding."
  tag "fix": "Configure the operating system to implement multifactor authentication
for remote access to privileged accounts via pluggable authentication modules (PAM).

Modify all of the services lines in /etc/sssd/sssd.conf to include pam."

# its('services") doesn't appear to be working properly
# added a test with grep to make sure one will pass if pam exists.
  describe.one do
     describe parse_config_file('/etc/sssd/sssd.conf') do
       its('services') { should include 'pam' }
     end
     describe command(" grep -i -E 'services(\s)*=(\s)*(.+*)pam' /etc/sssd/sssd.conf ") do
       its('stdout.strip') { should include 'pam' }
     end
  end
  
end
