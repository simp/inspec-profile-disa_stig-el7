control 'SV-204416' do
  title 'The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store only
    encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords.
    If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords
    encrypted with a weak algorithm are no more protected than if they are kept in plain text.'
  desc 'rationale', ''
  desc 'check', %q(Verify the system's shadow file is configured to store only encrypted representations of passwords.
    The strength of encryption that must be used to hash passwords for all accounts is SHA512.
    Check that the system is configured to create SHA512 hashed passwords with the following command:
    # grep -i encrypt /etc/login.defs
    ENCRYPT_METHOD SHA512
    If the "/etc/login.defs" configuration file does not exist or allows for password hashes other than SHA512 to be
    used, this is a finding.)
  desc 'fix', 'Configure the operating system to store only SHA512 encrypted representations of passwords.
    Add or update the following line in "/etc/login.defs":
    ENCRYPT_METHOD SHA512'
  impact 0.5
  tag 'legacy': ['V-71921', 'SV-86545']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000073-GPOS-00041'
  tag 'gid': 'V-204416'
  tag 'rid': 'SV-204416r603261_rule'
  tag 'stig_id': 'RHEL-07-010210'
  tag 'fix_id': 'F-4540r88441_fix'
  tag 'cci': ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
  tag subsystems: ['login_defs', 'password']
  tag 'host', 'container'

  describe login_defs do
    its('ENCRYPT_METHOD') { should cmp 'SHA512' }
  end
end
