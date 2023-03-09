control 'SV-204595' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to
    only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2
    hash algorithm meeting this requirement is SHA.
    The system will attempt to use the first hash presented by the client that matches the server list. Listing the
    values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH
    connection.'
  desc 'rationale', ''
  desc 'check', 'Verify the SSH daemon is configured to only use MACs employing FIPS 140-2-approved hashes.
    Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS
    140-2-approved cryptographic algorithms and hashes.
    Check that the SSH daemon is configured to only use MACs employing FIPS 140-2-approved hashes with the following
    command:
    # grep -i macs /etc/ssh/sshd_config
    MACs hmac-sha2-512,hmac-sha2-256
    If any hashes other than "hmac-sha2-512" or "hmac-sha2-256" are listed, the order differs from the example above,
    they are missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "MACs" keyword and set its
    value to "hmac-sha2-512" and/or "hmac-sha2-256" (this file may be named differently or be in a different location if
    using a version of SSH that is provided by a third-party vendor):
    MACs hmac-sha2-512,hmac-sha2-256
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag 'legacy': ['SV-86877', 'V-72253']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000250-GPOS-00093'
  tag 'gid': 'V-204595'
  tag 'rid': 'SV-204595r744117_rule'
  tag 'stig_id': 'RHEL-07-040400'
  tag 'fix_id': 'F-4719r622309_fix'
  tag 'cci': ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else

    macs = sshd_config.params('macs')
    if macs.nil?
      # fail fast
      describe 'The `sshd_config` setting for `MACs`' do
        subject { macs }
        it 'should be explicitly set and not commented out' do
          expect(subject).not_to be_nil
        end
      end
    else
      describe 'The list of MACs enabled on the system' do
        subject { macs }
        it { should cmp 'hmac-sha2-512,hmac-sha2-256' }
      end
    end
  end
end
