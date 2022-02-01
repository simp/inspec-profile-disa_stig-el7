control 'SV-204448' do
  title 'The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service
    packs, device drivers, or operating system components of local packages without verification they have been
    digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved
    by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating
    system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted
    vendor.
    Accordingly, patches, service packs, device drivers, or operating system components must be signed with a
    certificate recognized and approved by the organization.
    Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade
    received from a vendor. This verifies the software has not been tampered with and that it has been provided by a
    trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to
    verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the
    certificate used to verify the software must be from an approved CA.'
  tag 'legacy': ['V-71979', 'SV-86603']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system prevents the installation of patches, service packs, device drivers, or
    operating system components of local packages without verification that they have been digitally signed using a
    certificate that is recognized and approved by the organization.
    Check that yum verifies the signature of local packages prior to install with the following command:
    # grep localpkg_gpgcheck /etc/yum.conf
    localpkg_gpgcheck=1
    If "localpkg_gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator
    how the signatures of local packages and other operating system components are verified.
    If there is no process to validate the signatures of local packages that is approved by the organization, this is a
    finding.'
  desc 'fix', 'Configure the operating system to verify the signature of local packages prior to install by setting
    the following option in the "/etc/yum.conf" file:
    localpkg_gpgcheck=1'
  impact 0.7
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000366-GPOS-00153'
  tag 'gid': 'V-204448'
  tag 'rid': 'SV-204448r603261_rule'
  tag 'stig_id': 'RHEL-07-020060'
  tag 'fix_id': 'F-4572r88537_fix'
  tag 'cci': ['CCI-001749']
  tag nist: ['CM-5 (3)']

  yum_conf = '/etc/yum.conf'

  if (f = file(yum_conf)).exist?
    describe ini(yum_conf) do
      its('main.localpkg_gpgcheck') { cmp 1 }
    end
  else
    describe f do
      it { should exist }
    end
  end
end
