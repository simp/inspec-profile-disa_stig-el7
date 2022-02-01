control 'SV-204607' do
  title 'The Red Hat Enterprise Linux operating system must not contain shosts.equiv files.'
  desc 'The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based
    authentication is not sufficient for preventing unauthorized access to the system, as it does not require
    interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  tag 'legacy': ['SV-86903', 'V-72279']
  desc 'rationale', ''
  desc 'check', 'Verify there are no "shosts.equiv" files on the system.
    Check the system for the existence of these files with the following command:
    # find / -name shosts.equiv
    If any "shosts.equiv" files are found on the system, this is a finding.'
  desc 'fix', 'Remove any found "shosts.equiv" files from the system.
    # rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.7
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204607'
  tag 'rid': 'SV-204607r603261_rule'
  tag 'stig_id': 'RHEL-07-040550'
  tag 'fix_id': 'F-4731r89014_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('find / -xdev -xautofs -name shosts.equiv') do
    its('stdout.strip') { should be_empty }
  end
end
