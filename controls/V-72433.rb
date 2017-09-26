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

control "V-72433" do
  title "The operating system must implement certificate status checking for PKI
authentication."
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
  tag "gid": "V-72433"
  tag "rid": "SV-87057r2_rule"
  tag "stig_id": "RHEL-07-041003"
  tag "cci": "CCI-001948"
  tag "nist": ["IA-2 (11)", "Rev_4"]
  tag "cci": "CCI-001953"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "cci": "CCI-001954"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "check": "Verify the operating system implements certificate status checking
for PKI authentication.

Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system
with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf

cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;

There should be at least three lines returned. All lines must match the example
output; specifically that \"ocsp_on\" must be included in the \"cert_policy\" line.

If \"ocsp_on\" is present in all \"cert_policy\" lines, this is not a finding."
  tag "fix": "Configure the operating system to do certificate status checking for
PKI authentication.

Modify all of the \"cert_policy\" lines in \"/etc/pam_pkcs11/pam_pkcs11.conf\" to
include \"ocsp_on\"."

  describe command("grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf") do
    its('stdout') { should include 'ocsp_on' }
  end

  describe command("grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | wc -l") do
    its('stdout.strip.to_i') { should cmp >= 3 }
  end

end
