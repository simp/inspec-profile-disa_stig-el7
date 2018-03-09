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
                           'V_72435_Smart_Card_Status',
                           default: "enabled",
                           description: 'Smart Card Status'
                         )
						 
control "V-72435" do
  title "The operating system must implement smart card logons for multifactor
authentication for access to privileged accounts."
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
  tag "gid": "V-72435"
  tag "rid": "SV-87059r2_rule"
  tag "stig_id": "RHEL-07-041004"
  tag "cci": "CCI-001948"
  tag "nist": ["IA-2 (11)", "Rev_4"]
  tag "cci": "CCI-001953"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "cci": "CCI-001954"
  tag "nist": ["IA-2 (12)", "Rev_4"]
  tag "check": "Verify the operating system requires smart card logons for
multifactor authentication to uniquely identify privileged users.

Check to see if smartcard authentication is enforced on the system with the
following command:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for logon may be enabled, and the smartcard module
and smartcard removal actions must not be blank.

If smartcard authentication is disabled or the smartcard and smartcard removal
actions are blank, this is a finding."

  tag "fix": "Configure the operating system to implement smart card logon for
multifactor authentication to uniquely identify privileged users.

Enable smart card logons with the following commands:

# authconfig --enablesmartcard --smartcardaction=1 --update
# authconfig --enablerequiresmartcard --update"


  describe command("authconfig --test | grep -i \"smartcard for login is\" | awk '{ print $NF }'") do
    its('stdout.strip') { should eq "#{smart_card_status}" }
  end

  describe command('authconfig --test | grep -i "smartcard removal action" | awk \'{ print $NF }\'') do
    its('stdout.strip') { should_not be nil }
  end

end
