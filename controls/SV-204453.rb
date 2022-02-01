control 'SV-204453' do
  title 'The Red Hat Enterprise Linux operating system must enable SELinux.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure
    may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system
    responsible for enforcing the system security policy and supporting the isolation of code and data on which the
    protection is based. Security functionality includes, but is not limited to, establishing system accounts,
    configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting
    intrusion detection parameters.
    This requirement applies to operating systems performing security function verification/testing and/or systems and
    environments that require this functionality.'
  tag 'legacy': ['V-71989', 'SV-86613']
  tag 'rationale': ''
  tag 'check': 'Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in
    conjunction with SELinux.
    Verify the operating system verifies correct operation of all security functions.
    Check if "SELinux" is active and in "Enforcing" mode with the following command:
    # getenforce
    Enforcing
    If "SELinux" is not active and not in "Enforcing" mode, this is a finding.'
  tag 'fix': 'Configure the operating system to verify correct operation of all security functions.
    Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following
    line:
    SELINUX=enforcing
    A reboot is required for the changes to take effect.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000445-GPOS-00199'
  tag 'gid': 'V-204453'
  tag 'rid': 'SV-204453r754746_rule'
  tag 'stig_id': 'RHEL-07-020210'
  tag 'fix_id': 'F-36306r602628_fix'
  tag 'cci': ['CCI-002165', 'CCI-002696']
  tag nist: ['AC-3 (4)', 'SI-6 a']

  if package('MFEhiplsm').installed? && processes(/hipclient/).exist?
    impact 0.0
    describe 'HIPS is active on the system' do
      skip 'A HIPS process is active on the system, this control is Not Applicable.'
    end
  elsif service('cma').installed? && service('cma').enabled?
    impact 0.0
    describe 'HBSS is active on the system' do
      skip 'A HBSS service is active on the system, this control is Not Applicable.'
    end
  else
    impact 0.7
    describe command('getenforce') do
      its('stdout.strip') { should eq 'Enforcing' }
    end
  end
end
