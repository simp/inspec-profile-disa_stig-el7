# encoding: utf-8
#

# Smart Card Preference
#
# Per Redhat - Do not use the --enablerequiresmartcard option until you have
# successfully authenticated to the system using a smart card. Otherwise,
# users may be unable to log into the system.
#

smart_card_status = input(
  'smart_card_status',
  value: 'enabled', # values(enabled|disabled)
  description: 'Smart Card Status'
)

control "V-71965" do
  title "The operating system must uniquely identify and must authenticate
organizational users (or processes acting on behalf of organizational users)
using multifactor authentication."
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

    2) Accesses that occur through authorized use of group authenticators
without individual authentication. Organizations may require unique
identification of individuals in group accounts (e.g., shared privilege
accounts) or for detailed accountability of individual activity.
  "
  if smart_card_status.eql?('enabled')
  impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000104-GPOS-00051"
  tag "satisfies": ["SRG-OS-000104-GPOS-00051", "SRG-OS-000106-GPOS-00053",
"SRG-OS-000107-GPOS-00054", "SRG-OS-000109-GPOS-00056",
"SRG-OS-000108-GPOS-00055", "SRG-OS-000108-GPOS-00057",
"SRG-OS-000108-GPOS-00058"]
  tag "gid": "V-71965"
  tag "rid": "SV-86589r1_rule"
  tag "stig_id": "RHEL-07-010500"
  tag "cci": ["CCI-000766"]
  tag "documentable": false
  tag "nist": ["IA-2 (2)", "Rev_4"]
  tag "subsystems": ['pam', 'smartcard']
  desc "check", "Verify the operating system requires multifactor authentication
to uniquely identify organizational users using multifactor authentication.

Check to see if smartcard authentication is enforced on the system:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for logon may be enabled, and the smartcard
module and smartcard removal actions must not be blank.

If smartcard authentication is disabled or the smartcard and smartcard removal
actions are blank, this is a finding."
  desc "fix", "Configure the operating system to require individuals to be
authenticated with a multifactor authenticator.

Enable smartcard logons with the following commands:

# authconfig --enablesmartcard --smartcardaction=1 --update
# authconfig --enablerequiresmartcard -update

Modify the \"/etc/pam_pkcs11/pkcs11_eventmgr.conf\" file to uncomment the
following line:

#/usr/X11R6/bin/xscreensaver-command -lock

Modify the \"/etc/pam_pkcs11/pam_pkcs11.conf\" file to use the cackey module if
required."
  tag "fix_id": "F-78317r1_fix"
  describe command("authconfig --test | grep -i smartcard") do
    its('stdout') { should match %r{use\sonly\ssmartcard\sfor\slogin\sis\s#{smart_card_status}} }
    its('stdout') { should match %r{smartcard\smodule\s=\s".+"} }
    its('stdout') { should match %r{smartcard\sremoval\saction\s=\s".+"} }
  end if smart_card_status.eql?('enabled')

  describe "The system is not smartcard enabled" do
    skip "The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable."
  end if !smart_card_status.eql?('enabled')
end
