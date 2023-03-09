control 'SV-204434' do
  title 'The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system does not allow users to override environment variables to the SSH
    daemon.
    Check for the value of the "PermitUserEnvironment" keyword with the following command:
    # grep -i permituserenvironment /etc/ssh/sshd_config
    PermitUserEnvironment no
    If the "PermitUserEnvironment" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to not allow users to override environment variables to the SSH daemon.
    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "PermitUserEnvironment" keyword and set the
    value to "no":
    PermitUserEnvironment no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag 'legacy': ['SV-86581', 'V-71957']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00229'
  tag 'gid': 'V-204434'
  tag 'rid': 'SV-204434r603261_rule'
  tag 'stig_id': 'RHEL-07-010460'
  tag 'fix_id': 'F-4558r88495_fix'
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
      its('PermitUserEnvironment') { should eq 'no' }
    end
  end
end
