control 'SV-204443' do
  title 'The Red Hat Enterprise Linux operating system must not have the ypserv package installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or
    NIS+ services.'
  desc 'rationale', ''
  desc 'check', 'The NIS service provides an unencrypted authentication service that does not provide for the
    confidentiality and integrity of user passwords or the remote session.
    Check to see if the "ypserve" package is installed with the following command:
    # yum list installed ypserv
    If the "ypserv" package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by removing the "ypserv" package
    from the system with the following command:
    # yum remove ypserv'
  impact 0.7
  tag 'legacy': ['V-71969', 'SV-86593']
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000095-GPOS-00049'
  tag 'gid': 'V-204443'
  tag 'rid': 'SV-204443r603261_rule'
  tag 'stig_id': 'RHEL-07-020010'
  tag 'fix_id': 'F-4567r88522_fix'
  tag 'cci': ['CCI-000381']
  tag nist: ['CM-7 a']
  tag subsystems: ['packages']
  tag 'host', 'container'

  describe package('ypserv') do
    it { should_not be_installed }
  end
end
