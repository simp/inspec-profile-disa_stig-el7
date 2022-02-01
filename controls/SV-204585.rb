control 'SV-204585' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH
    installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because
    unprotected communications can be intercepted and either read or altered.
    This requirement applies to both internal and external networks and all types of information system components from
    which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers,
    scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are
    exposed to the possibility of interception and modification.
    Protecting the confidentiality and integrity of organizational information can be accomplished by physical means
    (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If
    physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.'
  tag 'legacy': ['SV-86857', 'V-72233']
  desc 'rationale', ''
  desc 'check', %q(Check to see if sshd is installed with the following command:
    # yum list installed \*ssh\*
    libssh2.x86_64 1.4.3-8.el7 @anaconda/7.1
    openssh.x86_64 6.6.1p1-11.el7 @anaconda/7.1
    openssh-server.x86_64 6.6.1p1-11.el7 @anaconda/7.1
    If the "SSH server" package is not installed, this is a finding.)
  desc 'fix', 'Install SSH packages onto the host with the following commands:
    # yum install openssh-server.x86_64'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000423-GPOS-00187'
  tag 'satisfies': ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189',
                    'SRG-OS-000426-GPOS-00190']
  tag 'gid': 'V-204585'
  tag 'rid': 'SV-204585r603261_rule'
  tag 'stig_id': 'RHEL-07-040300'
  tag 'fix_id': 'F-4709r88948_fix'
  tag 'cci': ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']

  describe package('openssh-server') do
    it { should be_installed }
  end
  describe package('openssh-clients') do
    it { should be_installed }
  end
end
