# encoding: utf-8
#

#TODO This will change as the sha values goes up - make me an attrib for MIN_SHA_VAL

control "V-71919" do
  title "The PAM system service must be configured to store only encrypted
representations of passwords."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised. Passwords
encrypted with a weak algorithm are no more protected than if they are kept in
plain text."
  impact 0.5
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "gid": "V-71919"
  tag "rid": "SV-86543r2_rule"
  tag "stig_id": "RHEL-07-010200"
  tag "cci": ["CCI-000196"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "subsystems": ['pam', 'password']
  desc "check", "Verify the PAM system service is configured to store only
encrypted representations of passwords. The strength of encryption that must be
used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the
following command:

# grep password /etc/pam.d/system-auth-ac
password sufficient pam_unix.so sha512

If the \"/etc/pam.d/system-auth-ac\" configuration files allow for password
hashes other than SHA512 to be used, this is a finding."
  desc "fix", "Configure the operating system to store only SHA512 encrypted
representations of passwords.

Add the following line in \"/etc/pam.d/system-auth-ac\":

password sufficient pam_unix.so sha512"
  tag "fix_id": "F-78271r2_fix"

  describe pam("/etc/pam.d/system-auth") do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
    its('lines') { should match_pam_rule('password .* pam_unix.so').all_without_args('^(md5|bigcrypt|sha256|blowfish)$') }
  end
end
