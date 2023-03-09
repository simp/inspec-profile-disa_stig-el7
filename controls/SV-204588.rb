control 'SV-204588' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow
    authentication using RSA rhosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will
    require a password, even in the event of misconfiguration elsewhere.'
  desc 'rationale', ''
  desc 'check', %q(Check the version of the operating system with the following command:
    # cat /etc/redhat-release
    If the release is 7.4 or newer this requirement is Not Applicable.
    Verify the SSH daemon does not allow authentication using RSA rhosts authentication.
    To determine how the SSH daemon's "RhostsRSAAuthentication" option is set, run the following command:
    # grep RhostsRSAAuthentication /etc/ssh/sshd_config
    RhostsRSAAuthentication no
    If the value is returned as "yes", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using RSA rhosts authentication.
    Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":
    RhostsRSAAuthentication no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag 'legacy': ['V-72239', 'SV-86863']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204588'
  tag 'rid': 'SV-204588r603261_rule'
  tag 'stig_id': 'RHEL-07-040330'
  tag 'fix_id': 'F-4712r88957_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('RhostsRSAAuthentication') { should cmp 'no' }
    end
  end
end
