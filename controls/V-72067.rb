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

GRUB_CONF_PATH = attribute(
  'grub_conf_path',
  description: 'the default path for the grub.conf file',
  default: inspec.file('/boot/efi/EFI/redhat/grub.cfg').exist? ? '/boot/efi/EFI/redhat/grub.cfg' : '/boot/grub2/grub.cfg'
)

control "V-72067" do
  title "The operating system must implement NIST FIPS-validated cryptography for
the following: to provision digital signatures, to generate cryptographic hashes,
and to protect data requiring data-at-rest protections in accordance with applicable
federal laws, Executive Orders, directives, policies, regulations, and standards."
  desc  "
    Use of weak or untested encryption algorithms undermines the purposes of using
encryption to protect data. The operating system must implement cryptographic
modules adhering to the higher standards approved by the federal government since
this provides assurance they have been tested and validated.

    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000185-GPOS-00079,
SRG-OS-000396-GPOS-00176, SRG-OS-000405-GPOS-00184, SRG-OS-000478-GPOS-0022.
  "
  impact 0.7

  tag "gtitle": "SRG-OS-000033-GPOS-00014"
  tag "gid": "V-72067"
  tag "rid": "SV-86691r2_rule"
  tag "stig_id": "RHEL-07-021350"
  tag "cci": ["CCI-000068","CCI-001199","CCI-002450","CCI-002476"]
  tag "nist": ["AC-17 (2)","SC-28","SC-13","SC-28 (1)","Rev_4"]
  tag "check": "Verify the operating system implements DoD-approved encryption to
protect the confidentiality of remote access sessions.

Check to see if the \"dracut-fips\" package is installed with the following command:

# yum list installed | grep dracut-fips

dracut-fips-033-360.el7_2.x86_64.rpm

If a \"dracut-fips\" package is installed, check to see if the kernel command line
is configured to use FIPS mode with the following command:

Note: GRUB 2 reads its configuration from the \"/boot/grub2/grub.cfg\" file on
traditional BIOS-based machines and from the \"/boot/efi/EFI/redhat/grub.cfg\" file
on UEFI machines.

# grep fips /boot/grub2/grub.cfg
/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0
rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us
rd.lvm.lv=rhel/root rhgb fips=1 quiet

If the kernel command line is configured to use FIPS mode, check to see if the
system is in FIPS mode with the following command:

# cat /proc/sys/crypto/fips_enabled
1

If a \"dracut-fips\" package is not installed, the kernel command line does not have
a fips entry, or the system has a value of \"0\" for \"fips_enabled\" in
\"/proc/sys/crypto\", this is a finding."
  tag "fix": "Configure the operating system to implement DoD-approved encryption by
installing the dracut-fips package.

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the
kernel command line during system installation so key generation is done with
FIPS-approved algorithms and continuous monitoring tests in place.

Configure the operating system to implement DoD-approved encryption by following the
steps below:

The fips=1 kernel option needs to be added to the kernel command line during system
installation so that key generation is done with FIPS-approved algorithms and
continuous monitoring tests in place. Users should also ensure that the system has
plenty of entropy during the installation process by moving the mouse around, or if
no mouse is available, ensuring that many keystrokes are typed. The recommended
amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a
non-unique key.

For proper operation of the in-module integrity verification, the prelink has to be
disabled. This can be done by configuring PRELINKING=no in the
\"/etc/sysconfig/prelink\" configuration file. Existing prelinking, if any, should
be undone on all system files using the prelink -u -a command.

Install the dracut-fips package with the following command:

# yum install dracut-fips

Recreate the \"initramfs\" file with the following command:

Note: This command will overwrite the existing \"initramfs\" file.

# dracut -f

Modify the kernel command line of the current kernel in the \"grub.cfg\" file by
adding the following option to the GRUB_CMDLINE_LINUX key in the
\"/etc/default/grub\" file and then rebuild the \"grub.cfg\" file:

fips=1

Changes to \"/etc/default/grub\" require rebuilding the \"grub.cfg\" file as follows:

On BIOS-based machines, use the following command:

# grub2-mkconfig -o /boot/grub2/grub.cfg

On UEFI-based machines, use the following command:

# grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

If /boot or /boot/efi reside on separate partitions, the kernel parameter
boot=<partition of /boot or /boot/efi> must be added to the kernel command line. You
can identify a partition by running the df /boot or df /boot/efi command:

# df /boot
Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/sda1               495844     53780    416464  12% /boot

To ensure the boot= configuration option will work even if device naming changes
between boots, identify the universally unique identifier (UUID) of the partition
with the following command:

# blkid /dev/sda1
/dev/sda1: UUID=\"05c000f1-a213-759e-c7a2-f11b7424c797\" TYPE=\"ext4\"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect."

  describe package('dracut-fips') do
    it { should be_installed }
  end
  describe grub_conf(GRUB_CONF_PATH, 'default') do
    its('kernel') { should include 'fips=1'}
  end
  describe file('/proc/sys/crypto/fips_enabled') do
    its('content') { should match %r{^1\n} }
  end
end
