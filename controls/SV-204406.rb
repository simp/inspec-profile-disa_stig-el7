control 'SV-204406' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new
    passwords are established, pwquality must be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password.
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing
    and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to
    limit brute-force attacks on the system.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system uses "pwquality" to enforce the password complexity rules.
    Check for the use of "pwquality" with the following command:
    # cat /etc/pam.d/system-auth | grep pam_pwquality
    password required pam_pwquality.so retry=3
    If the command does not return an uncommented line containing the value "pam_pwquality.so", this is a finding.
    If the value of "retry" is set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to use "pwquality" to enforce password complexity rules.
    Add the following line to "/etc/pam.d/system-auth" (or modify the line to have the required value):
    password required pam_pwquality.so retry=3
    Note: The value of "retry" should be between "1" and "3".'
  impact 0.5
  tag 'legacy': ['SV-87811', 'V-73159']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000069-GPOS-00037'
  tag 'gid': 'V-204406'
  tag 'rid': 'SV-204406r603261_rule'
  tag 'stig_id': 'RHEL-07-010119'
  tag 'fix_id': 'F-4530r88411_fix'
  tag 'cci': ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
  tag subsystems: ['pam', 'pwquality', 'password']
  tag 'host', 'container'

  describe pam('/etc/pam.d/system-auth') do
    its('lines') { should match_pam_rule("password required pam_pwquality.so retry=#{input('retry')}") }
  end

  describe 'input value' do
    it 'for retry should be in line with maximum/minimum allowed values by policy' do
      expect(input('retry')).to be_between(1, input('max_retry'))
    end
  end
end
