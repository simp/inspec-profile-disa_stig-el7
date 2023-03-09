control 'SV-204435' do
  title 'The Red Hat Enterprise Linux operating system must not allow a non-certificate trusted host SSH logon to
    the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.
    Check for the value of the "HostbasedAuthentication" keyword with the following command:
    # grep -i hostbasedauthentication /etc/ssh/sshd_config
    HostbasedAuthentication no
    If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to not allow a non-certificate trusted host SSH logon to the system.
    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "HostbasedAuthentication" keyword and set the
    value to "no":
    HostbasedAuthentication no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag 'legacy': ['SV-86583', 'V-71959']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00229'
  tag 'gid': 'V-204435'
  tag 'rid': 'SV-204435r603261_rule'
  tag 'stig_id': 'RHEL-07-010470'
  tag 'fix_id': 'F-4559r88498_fix'
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
      its('HostbasedAuthentication') { should eq 'no' }
    end
  end
end
