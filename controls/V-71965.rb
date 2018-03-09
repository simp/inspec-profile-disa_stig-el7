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

# Smart Card Preference
#
# Per Redhat - Do not use the --enablerequiresmartcard option until you have 
# successfully authenticated to the system using a smart card. Otherwise, 
# users may be unable to log into the system.
#
smart_card_status = attribute(
                           'V_71965_Smart_Card_Status',
                           default: "enabled",
                           description: 'Smart Card Status'
                         )
						 
control "V-71965" do
  title "The operating system must uniquely identify and must authenticate
organizational users (or processes acting on behalf of organizational users) using
multifactor authentication."
  desc  "
    To assure accountability and prevent unauthenticated access, organizational
users must be identified and authenticated to prevent potential misuse and
compromise of the system.

    Organizational users include organizational employees or individuals the
organization deems to have equivalent status of employees (e.g., contractors).
Organizational users (and processes acting on behalf of users) must be uniquely
identified and authenticated to all accesses, except for the following:

    1) Accesses explicitly identified and documented by the organization.
Organizations document specific user actions that can be performed on the
information system without identification or authentication;

    and

    2) Accesses that occur through authorized use of group authenticators without
individual authentication. Organizations may require unique identification of
individuals in group accounts (e.g., shared privilege accounts) or for detailed
accountability of individual activity.

    Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053,
SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055,
SRG-OS-000108-GPOS-00057, SRG-OS-000108-GPOS-0005.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000104-GPOS-00051"
  tag "gid": "V-71965"
  tag "rid": "SV-86589r1_rule"
  tag "stig_id": "RHEL-07-010500"
  tag "cci": "CCI-000766"
  tag "nist": ["IA-2 (2)", "Rev_4"]
  tag "check": "Verify the operating system requires multifactor authentication to
uniquely identify organizational users using multifactor authentication.

Check to see if smartcard authentication is enforced on the system:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for logon may be enabled, and the smartcard module
and smartcard removal actions must not be blank.

If smartcard authentication is disabled or the smartcard and smartcard removal
actions are blank, this is a finding."
  tag "fix": "Configure the operating system to require individuals to be
authenticated with a multifactor authenticator.

Per Redhat - Do not use the --enablerequiresmartcard option until you have 
successfully authenticated to the system using a smart card. Otherwise, 
users may be unable to log into the system.

Enable smartcard logons with the following commands:

# authconfig --enablesmartcard --smartcardaction=1 --update
# authconfig --enablerequiresmartcard -update

Modify the \"/etc/pam_pkcs11/pkcs11_eventmgr.conf\" file to uncomment the following
line:

#/usr/X11R6/bin/xscreensaver-command -lock

Modify the \"/etc/pam_pkcs11/pam_pkcs11.conf\" file to use the cackey module if
required."

  describe command("authconfig --test | grep -i smartcard") do
    its('stdout') { should match /use only smartcard for login is #{smart_card_status}/ }
    its('stdout') { should match /smartcard module = ".+"/ }
    its('stdout') { should match /smartcard removal action = ".+"/ }
  end
end
