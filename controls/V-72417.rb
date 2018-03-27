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

mfa_pkg_list = attribute(
    'mfa_pkg_list',
    description: 'The list of packages needed for MFA on RHEL',
    default: [
      'esc',
      'pam_pkcs11',
      'authconfig-gtk',
    ])

control "V-72417" do
  title "The operating system must have the required packages for multifactor
        authentication installed."
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

    Satisfies:
      - SRG-OS-000375-GPOS-00160,
      - SRG-OS-000375-GPOS-00161,
      - SRG-OS-000375-GPOS-0016.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000375-GPOS-00160"
  tag "gid": "V-72417"
  tag "rid": "SV-87041r2_rule"
  tag "stig_id": "RHEL-07-041001"
  tag "cci": ["CCI-001948","CCI-001953","CCI-001954"]
  tag "nist": ["IA-2 (11)","IA-2 (12)","IA-2 (12)","Rev_4"]
  tag "pki","MFA","pam","pkcs11","networking"

  tag "check": "Verify the operating system has the packages required for
  multifactor authentication installed.

  Check for the presence of the packages required to support multifactor
  authentication with the following commands:

  # yum list installed esc
  esc-1.1.0-26.el7.noarch.rpm

  # yum list installed pam_pkcs11
  pam_pkcs11-0.6.2-14.el7.noarch.rpm

  # yum list installed authconfig-gtk
  authconfig-gtk-6.1.12-19.el7.noarch.rpm

  If the \"esc\", \"pam_pkcs11\", and \"authconfig-gtk\" packages are not installed,
  this is a finding."

  tag "fix": "Configure the operating system to implement multifactor authentication
  by installing the required packages.

  Install the \"esc\", \"pam_pkcs11\", \"authconfig\", and \"authconfig-gtk\" packages
  on the system with the following command:

  # yum install esc pam_pkcs11 authconfig-gtk"

  mfa_pkg_list.each do |pkg|
    describe package("#{pkg}") do
      it { should be_installed }
    end
  end

end
