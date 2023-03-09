control 'SV-204458' do
  title 'The Red Hat Enterprise Linux operating system must be a vendor supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches
    for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the
    system software.
    Red Hat offers the Extended Update Support (EUS) Add-On to a Red Hat Enterprise Linux subscription, for a fee, for
    those customers who wish to standardize on a specific minor release for an extended period. RHEL 7.7 marks the final
    minor release that EUS will be available, while 7.9 is the final minor release overall.'
  desc 'rationale', ''
  desc 'check', 'Verify the version of the operating system is vendor supported.
    Check the version of the operating system with the following command:
    # cat /etc/redhat-release
    Red Hat Enterprise Linux Server release 7.9 (Maipo)
    Current End of Extended Update Support for RHEL 7.6 is 31 May 2021.
    Current End of Extended Update Support for RHEL 7.7 is 30 August 2021.
    Current End of Maintenance Support for RHEL 7.9 is 30 June 2024.
    If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  tag 'legacy': ['SV-86621', 'V-71997']
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204458'
  tag 'rid': 'SV-204458r744100_rule'
  tag 'stig_id': 'RHEL-07-020250'
  tag 'fix_id': 'F-4582r462547_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['redhat_release']
  tag 'host', 'container'

  release = os.release

  EOMS_DATE = case release
              when /^7\.6/
                '31 May 2021'
              when /^7\.7/
                '30 August 2021'
              when /^7\.9/
                '30 June 2024'
              end

  describe "The release \"#{release}\" must still be within the support window, ending #{EOMS_DATE}" do
    subject { Date.today <= Date.parse(EOMS_DATE) }
    it { should be true }
  end
end
