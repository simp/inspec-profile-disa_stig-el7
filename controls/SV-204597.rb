control 'SV-204597' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files
    have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  tag 'legacy': ['V-72257', 'SV-86881']
  desc 'rationale', ''
  desc 'check', %q(Verify the SSH private host key files have mode "0600" or less permissive.
    The following command will find all SSH private key files on the system and list their modes:
    # find / -name '*ssh_host*key' | xargs ls -lL
    -rw------- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
    -rw------- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
    -rw------- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key
    If any file has a mode more permissive than "0600", this is a finding.)
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0600" with the following
    command:
    # chmod 0600 /path/to/file/ssh_host*key'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204597'
  tag 'rid': 'SV-204597r792834_rule'
  tag 'stig_id': 'RHEL-07-040420'
  tag 'fix_id': 'F-4721r792833_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  key_files = command("find /etc/ssh -xdev -name '*ssh_host*key'").stdout.split("\n")
  if !key_files.nil? and !key_files.empty?
    key_files.each do |keyfile|
      describe file(keyfile) do
        it { should_not be_more_permissive_than('0640') }
      end
    end
  else
    describe 'No files have a more permissive mode.' do
      subject { key_files.nil? or key_files.empty? }
      it { should eq true }
    end
  end
end
