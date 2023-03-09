control 'SV-204451' do
  title 'The Red Hat Enterprise Linux operating system must disable the file system automounter unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating
    malicious activity.'
  desc 'rationale', ''
  desc 'check', 'Verify the operating system disables the ability to automount devices.
    Check to see if automounter service is active with the following command:
    # systemctl status autofs
    autofs.service - Automounts filesystems on demand
    Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
    Active: inactive (dead)
    If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO)
    as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to automount devices.
    Turn off the automount service with the following commands:
    # systemctl stop autofs
    # systemctl disable autofs
    If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.'
  impact 0.5
  tag 'legacy': ['V-71985', 'SV-86609']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000114-GPOS-00059'
  tag 'satisfies': ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163',
                    'SRG-OS-000480-GPOS-00227']
  tag 'gid': 'V-204451'
  tag 'rid': 'SV-204451r603261_rule'
  tag 'stig_id': 'RHEL-07-020110'
  tag 'fix_id': 'F-4575r88546_fix'
  tag 'cci': ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
  tag subsystems: ['file_system', 'nfs', 'autofs']
  tag 'host', 'container'

  describe systemd_service('autofs.service') do
    it { should_not be_running }
    it { should_not be_enabled }
    it { should_not be_installed }
  end
end
