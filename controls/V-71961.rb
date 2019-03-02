# encoding: utf-8
#

grub_superuser = attribute(
  'grub_superuser',
  description: 'superuser for grub boot',
  default: 'root'
)
grub_user_boot_files = attribute(
 'grub_user_boot_files',
 description: 'grub boot config files',
 default: ['/boot/grub2/user.cfg']
)
grub_main_cfg = attribute(
 'grub_main_cfg',
 description: 'main grub boot config file',
 default: '/boot/grub2/grub.cfg'
)

control "V-71961" do
  title "Systems with a Basic Input/Output System (BIOS) must require
authentication upon booting into single-user and maintenance modes."
  desc  "If the system does not require valid root authentication before it
boots into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 7 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu."
  impact 0.7
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-71961"
  tag "rid": "SV-86585r4_rule"
  tag "stig_id": "RHEL-07-010480"
  tag "cci": ["CCI-000213"]
  tag "documentable": false
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "For systems that use UEFI, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use a BIOS,
use the following command:

# grep -i ^password_pbkdf2 /boot/grub2/grub.cfg

password_pbkdf2 [superusers-account] [password-hash]

If the root password entry does not begin with \"password_pbkdf2\", this is a
finding.

If the \"superusers-account\" is not set to \"root\", this is a finding."
  tag "fix": "Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub2-mkpasswd-pbkdf2

Enter Password:
Reenter Password:
PBKDF2 hash of your password is
grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Edit \"/etc/grub.d/40_custom\" and add the following lines below the comments:

# vi /etc/grub.d/40_custom

set superusers=\"root\"

password_pbkdf2 root {hash from grub2-mkpasswd-pbkdf2 command}

Generate a new \"grub.conf\" file with the new password with the following
commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/grub2/grub.cfg
"
  tag "fix_id": "F-78313r2_fix"

  pattern = %r{\s*set superusers=\"(\w+)\"}i

  matches = file(grub_main_cfg).content.match(pattern)
  superusers = matches.nil? ? [] : matches.captures
  describe "There must be only one grub2 superuser, and it must have the value #{grub_superuser}" do
    subject { superusers }
    its('length') { should cmp 1 }
    its('first') { should cmp grub_superuser }
  end

  # Need each password entry that has the superuser
  pattern = %r{(.*)\s#{grub_superuser}\s}i
  matches = file(grub_main_cfg).content.match(pattern)
  password_entries = matches.nil? ? [] : matches.captures
  describe 'The grub2 superuser password entry must begin with \'password_pbkdf2\'' do
    subject { password_entries }
    its('length') { is_expected.to be >= 1}
    password_entries.each do |entry|
      subject { entry }
      it { should include 'password_pbkdf2'}
    end
  end

  pattern = %r{.*\sroot\s(\${\w+})}i
  matches = file(grub_main_cfg).content.match(pattern)
  env_vars = matches.nil? ? [] : matches.captures
  # Is there a problem if there is no environment variable?
  # Maybe only if there is also not the 'grub.pbkdf2' stuff...

  # Sort through these first to avoid cases where we don't hit a describe.
  next unless file(user_cfg_file).exist?


  grub_user_boot_files.each do |user_cfg_file|
    describe file(user_cfg_file) do
        its('content') { should match %r{^GRUB2_PASSWORD=grub.pbkdf2 } }
      end
    end
  end
end
