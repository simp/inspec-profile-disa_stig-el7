control 'SV-204422' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that passwords are prohibited from
    reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at
    guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse
    their password when that password has exceeded its defined lifetime, the end result is a password that is not
    changed per policy requirements.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system prohibits password reuse for a minimum of five generations.
    Check for the value of the "remember" argument in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" with the
    following command:
    # grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth
    password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3
    If the line containing the "pam_pwhistory.so" line does not have the "remember" module argument set, is commented
    out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit password reuse for a minimum of five generations.
    Add the following line in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" (or modify the line to have the
    required value):
    password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3
    Note: Manual changes to the listed files may be overwritten by the "authconfig" program. The "authconfig" program
    should not be used to update the configurations listed in this requirement.'
  impact 0.5
  tag 'legacy': ['V-71933', 'SV-86557']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000077-GPOS-00045'
  tag 'gid': 'V-204422'
  tag 'rid': 'SV-204422r603261_rule'
  tag 'stig_id': 'RHEL-07-010270'
  tag 'fix_id': 'F-4546r88459_fix'
  tag 'cci': ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
  tag subsystems: ["pam","password"]
  tag 'host', 'container'

  reuse_generations = input('expected_reuse_generations')

  describe.one do
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule("password (required|requisite|sufficient) pam_(unix|pwhistory).so remember=#{reuse_generations}") }
    end
    describe pam('/etc/pam.d/password-auth') do
      its('lines') {
        should match_pam_rule("password (required|requisite|sufficient) pam_(unix|pwhistory).soremember=#{reuse_generations}") }
    end
  end

  describe "input value" do
    it "for reuse_generations should be in line with maximum/minimum allowed values by policy" do
      expect(input('expected_reuse_generations')).to cmp >= input('min_reuse_generations')
    end
  end
end
