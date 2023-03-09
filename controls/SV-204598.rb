control 'SV-204598' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit
    Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing
    GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the
    system. GSSAPI authentication must be disabled unless needed."
  desc 'rationale', ''
  desc 'check', 'Verify the SSH daemon does not permit GSSAPI authentication unless approved.
    Check that the SSH daemon does not permit GSSAPI authentication with the following command:
    # grep -i gssapiauth /etc/ssh/sshd_config
    GSSAPIAuthentication no
    If the "GSSAPIAuthentication" keyword is missing, is set to "yes" and is not documented with the Information System
    Security Officer (ISSO), or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "GSSAPIAuthentication" keyword in "/etc/ssh/sshd_config" (this file may be named
    differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and
    set the value to "no":
    GSSAPIAuthentication no
    The SSH service must be restarted for changes to take effect.
    If GSSAPI authentication is required, it must be documented, to include the location of the configuration file, with
    the ISSO.'
  impact 0.5
  tag 'legacy': ['V-72259', 'SV-86883']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000364-GPOS-00151'
  tag 'gid': 'V-204598'
  tag 'rid': 'SV-204598r603261_rule'
  tag 'stig_id': 'RHEL-07-040430'
  tag 'fix_id': 'F-4722r88987_fix'
  tag 'cci': ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813',
              'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1)', 'CM-5 (1)']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  elsif input('gssapi_approved')
    describe sshd_config do
      its('GSSAPIAuthentication') { should cmp 'no' }
    end
  else
    impact 0.0
    describe 'GSSAPI authentication is not approved' do
      skip 'GSSAPI authentication is not approved, this control is Not Applicable.'
    end
  end
end
