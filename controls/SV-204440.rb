control 'SV-204440' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer using Unified Extensible Firmware Interface
    (UEFI) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode,
    anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2
    is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make
    modifications to the boot menu.'
  desc 'rationale', ''
  desc 'check', 'For systems that use BIOS, this is Not Applicable.
    For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.
    Check to see if an encrypted grub superusers password is set. On systems that use UEFI, use the following command:
    $ sudo grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
    GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]
    If the grub superusers password does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for the grub superusers account with the
    grub2-setpassword command, which creates/overwrites the /boot/efi/EFI/redhat/user.cfg file.
    Generate an encrypted grub2 password for the grub superusers account with the following command:
    $ sudo grub2-setpassword
    Enter password:
    Confirm password:'
  impact 0.7
  tag 'legacy': ['SV-95719', 'V-81007']
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-204440'
  tag 'rid': 'SV-204440r744098_rule'
  tag 'stig_id': 'RHEL-07-010491'
  tag 'fix_id': 'F-4564r744097_fix'
  tag 'cci': ['CCI-000213']
  tag nist: ['AC-3']
  tag subsystems: ['boot', 'uefi']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif file('/sys/firmware/efi').exist?

    if os[:release] >= '7.2'
      impact 0.7
      input('grub_uefi_user_boot_files').each do |grub_user_file|
        describe parse_config_file(grub_user_file) do
          its('GRUB2_PASSWORD') { should include 'grub.pbkdf2.sha512' }
        end
      end

      describe parse_config_file(input('grub_uefi_main_cfg')) do
        its('set superusers') { should cmp '"root"' }
      end
    else
      impact 0.0
      describe 'System running version of RHEL prior to 7.2' do
        skip 'The System is running an outdated version of RHEL, this control is Not Applicable.'
      end
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running BIOS, this control is Not Applicable.'
    end
  end
end
