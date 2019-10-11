# encoding: utf-8
#

smart_card_status = input(
  'smart_card_status',
  value: 'enabled', # values(enabled|disabled)
  description: 'Smart Card Status'
)

control "V-72433" do
  title "The operating system must implement certificate status checking for
PKI authentication."
  desc  "
    Using an authentication device, such as a CAC or token that is separate
from the information system, ensures that even if the information system is
compromised, that compromise will not affect credentials stored on the
authentication device.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification card and the DoD Common Access
Card.

    A privileged account is defined as an information system account with
authorizations of a privileged user.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    This requirement only applies to components where this is specific to the
function of the device or has the concept of an organizational user (e.g., VPN,
proxy capability). This does not apply to authentication for the purpose of
configuring the device itself (management).

    Requires further clarification from NIST.
  "
if smart_card_status.eql?('enabled')
  impact 0.5
else
  impact 0.0
end
  tag "gtitle": "SRG-OS-000375-GPOS-00160"
  tag "satisfies": ["SRG-OS-000375-GPOS-00160", "SRG-OS-000375-GPOS-00161",
"SRG-OS-000375-GPOS-00162"]
  tag "gid": "V-72433"
  tag "rid": "SV-87057r4_rule"
  tag "stig_id": "RHEL-07-041003"
  tag "cci": ["CCI-001948", "CCI-001953", "CCI-001954"]
  tag "documentable": false
  tag "nist": ["IA-2 (11)", "IA-2 (12)", "IA-2 (12)", "Rev_4"]
  tag "subsystems": ['pam_pkcs11', 'pam' , 'pkcs11']
  desc "check", "Verify the operating system implements certificate status
checking for PKI authentication.

Check to see if Online Certificate Status Protocol (OCSP) is enabled on the
system with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf

cert_policy = ca, ocsp_on, signature;
cert_policy = ca, ocsp_on, signature;
cert_policy = ca, ocsp_on, signature;


There should be at least three lines returned.

If \"oscp_on\" is not present in all \"cert_policy\" lines in
\"/etc/pam_pkcs11/pam_pkcs11.conf\", this is a finding.
"
  desc "fix", "Configure the operating system to do certificate status checking
for PKI authentication.

Modify all of the \"cert_policy\" lines in \"/etc/pam_pkcs11/pam_pkcs11.conf\"
to include \"ocsp_on\"."
  tag "fix_id": "F-78785r3_fix"

  if smart_card_status.eql?('enabled')
    if ((pam_file = file('/etc/pam_pkcs11/pam_pkcs11.conf')).exist?)
      cert_policy_lines = (pam_file.content.nil?)?[]:
        pam_file.content.lines.grep(%r{^(?!.+#).*cert_policy}i)
      if (cert_policy_lines.length < 3)
        describe "should contain at least 3 cert policy lines" do
          subject { cert_policy_lines.length }
          it { should >= 3 }
        end
      else
        describe "each cert policy line should include oscp_on" do
          cert_policy_lines.each do |line|                                    
            line.should match %r{=[^;]*ocsp_on}i                                        
          end 
        end                                                                                              
      end
    else 
      describe pam_file do
        it { should exist }
      end
    end
  else
    describe "The system is not smartcard enabled" do
      skip "The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable."
    end
  end
end
