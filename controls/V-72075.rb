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

control "V-72075" do
  title "The system must not allow removable media to be used as the boot loader
unless approved."
  desc  "Malicious users with removable boot media can gain access to a system
configured to use removable media as the boot loader. If removable media is designed
to be used as the boot loader, the requirement must be documented with the
Information System Security Officer (ISSO)."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000364-GPOS-00151"
  tag "gid": "V-72075"
  tag "rid": "SV-86699r1_rule"
  tag "stig_id": "RHEL-07-021700"
  tag "cci": "CCI-000318"
  tag "nist": ["CM-3 f", "Rev_4"]
  tag "cci": "CCI-000368"
  tag "nist": ["CM-6 c", "Rev_4"]
  tag "cci": "CCI-001812"
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "cci": "CCI-001813"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "cci": "CCI-001814"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "Verify the system is not configured to use a boot loader on
removable media.

Note: GRUB 2 reads its configuration from the \"/boot/grub2/grub.cfg\" file on
traditional BIOS-based machines and from the \"/boot/efi/EFI/redhat/grub.cfg\" file
on UEFI machines.

Check for the existence of alternate boot loader configuration files with the
following command:

# find / -name grub.cfg
/boot/grub2/grub.cfg

If a \"grub.cfg\" is found in any subdirectories other than \"/boot/grub2\" and
\"/boot/efi/EFI/redhat\", ask the System Administrator if there is documentation
signed by the ISSO to approve the use of removable media as a boot loader.

Check that the grub configuration file has the set root command in each menu entry
with the following commands:

# grep -c menuentry /boot/grub2/grub.cfg
1
# grep ‘set root’ /boot/grub2/grub.cfg
set root=(hd0,1)

If the system is using an alternate boot loader on removable media, and
documentation does not exist approving the alternate configuration, this is a
finding."
  tag "fix": "Remove alternate methods of booting the system from removable media or
document the configuration to boot from removable media with the ISSO."

  describe "The list of unapproved boot loader configuration files" do
    subject { 
      command('find / -name grub.cfg -type f').stdout.chomp.split 
    } 
    before { 
      subject.delete("/boot/grub2/grub.cfg") 
      subject.delete("/boot/efi/EFI/redhat/grub.cfg")
    }
    it { should eq [] }
  end
end
