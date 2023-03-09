control 'SV-244558' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user mode and maintenance.'
  desc  "If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.\nThe GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are root, superuser, unlock, etc."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag satisfies: nil
  tag gid: 'V-244558'
  tag rid: 'SV-244558r792840_rule'
  tag stig_id: 'RHEL-07-010492'
  tag fix_id: 'F-47790r744065_fix'
  tag cci: ['CCI-000213']
  tag legacy: []
  tag subsystems: ['grub']
  tag 'host', 'container'
  tag check: "For systems that use BIOS, this is Not Applicable.\n\nFor systems that are running a version of RHEL prior to 7.2, this is Not Applicable.\n\nVerify that a unique name is set as the \"superusers\" account:\n\n$ sudo grep -iw \"superusers\" /boot/efi/EFI/redhat/grub.cfg\n    set superusers=\"[someuniquestringhere]\"\n    export superusers\n\nIf \"superusers\" is identical to any OS account name or is missing a name, this is a finding."
  tag fix: "Configure the system to have a unique name for the grub superusers account.\n\nEdit the /boot/efi/EFI/redhat/grub.cfg file and add or modify the following lines in the \"### BEGIN /etc/grub.d/01_users ###\" section:\n\nset superusers=\"[someuniquestringhere]\"\nexport superusers\npassword_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}"

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif file('/sys/firmware/efi').exist?
    if os[:release] >= '7.2'
      describe parse_config_file(input('grub_uefi_main_cfg')) do
        its('set superusers') { should exist }
        its('set superusers') { should_not be_in users.usernames }
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
