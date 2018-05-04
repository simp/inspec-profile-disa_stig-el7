# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end
EFI_SUPERUSERS = attribute(
  'efi_superusers',
  description: 'superusers for efi boot ( array )',
  default: ['root']
)
EFI_USER_BOOT_FILES = attribute(
 'efi_user_boot_files',
 description: 'efi boot config files',
 default: ['/boot/efi/EFI/redhat/user.cfg']
)
EFI_MAIN_CFG = attribute(
 'efi_main_cfg',
 description: 'main efi boot config file',
 default: '/boot/efi/EFI/redhat/grub.cfg'
)

control "V-71963" do
  title "Systems using Unified Extensible Firmware Interface (UEFI) must require
authentication upon booting into single-user and maintenance modes."
  desc  "If the system does not require valid root authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or maintenance
mode is granted privileged access to all files on the system. GRUB 2 is the default
boot loader for RHEL 7 and is designed to require a password to boot into
single-user mode or make modifications to the boot menu."
  impact 0.7

  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-71963"
  tag "rid": "SV-86587r1_rule"
  tag "stig_id": "RHEL-07-010490"
  tag "cci": "CCI-000213"
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "Check to see if an encrypted root password is set. On systems that
use UEFI, use the following command:

# grep -i password /boot/efi/EFI/redhat/grub.cfg
password_pbkdf2 superusers-account password-hash

If the root password entry does not begin with \"password_pbkdf2\", this is a
finding."
  tag "fix": "Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub-mkpasswd-pbkdf2
Enter Password:
Reenter Password:

PBKDF2 hash of your password is
grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Using this hash, modify the \"/etc/grub.d/10_linux\" file with the following
commands to add the password to the root entry:

# cat << EOF
> set superusers=\"root\" password_pbkdf2 smithj
grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45
> EOF

Generate a new \"grub.conf\" file with the new password with the following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/efi/EFI/redhat/grub.cfg"

  describe file(EFI_MAIN_CFG) do
    its('content') { should match %r{^\s*password_pbkdf2\s+root } }
  end

  EFI_USER_BOOT_FILES.each do |user_cfg_file|
    next if !file(user_cfg_file).exist?
    describe.one do
      EFI_SUPERUSERS.each do |user|
        describe file(user_cfg_file) do
          its('content') { should match %r{^\s*password_pbkdf2\s+#{user} } }
        end
      end
    end
  end
end
