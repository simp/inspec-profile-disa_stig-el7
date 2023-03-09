control 'SV-204591' do
  title 'The Red Hat Enterprise Linux operating system must display the date and time of the last successful account
    logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition
    and reporting of unauthorized account use.'
  desc 'rationale', ''
  desc 'check', 'Verify SSH provides users with feedback on when account accesses last occurred.
    Check that "PrintLastLog" keyword in the sshd daemon configuration file is used and set to "yes" with the following
    command:
    # grep -i printlastlog /etc/ssh/sshd_config
    PrintLastLog yes
    If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to provide users with feedback on when account accesses last occurred by setting the
    required configuration options in "/etc/pam.d/sshd" or in the "sshd_config" file used by the system
    ("/etc/ssh/sshd_config" will be used in the example) (this file may be named differently or be in a different
    location if using a version of SSH that is provided by a third-party vendor).
    Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the following:
    PrintLastLog yes
    The SSH service must be restarted for changes to "sshd_config" to take effect.'
  impact 0.5
  tag 'legacy': ['V-72245', 'SV-86869']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204591'
  tag 'rid': 'SV-204591r603261_rule'
  tag 'stig_id': 'RHEL-07-040360'
  tag 'fix_id': 'F-4715r88966_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['pam', 'ssh', 'lastlog']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  elsif sshd_config.params['printlastlog'] == ['yes']

    describe sshd_config do
      its('PrintLastLog') { should cmp 'yes' }
    end
  else
    describe pam('/etc/pam.d/sshd') do
      its('lines') do
        should match_pam_rule('session required pam_lastlog.so showfailed')
      end
      its('lines') do
        should_not match_pam_rule('session required pam_lastlog.so showfailed silent')
      end
    end
  end
end
