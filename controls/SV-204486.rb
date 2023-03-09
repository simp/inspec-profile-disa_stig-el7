control 'SV-204486' do
  title 'The Red Hat Enterprise Linux operating system must mount /dev/shm with secure options.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for
    mounting any file system not containing approved binary files as they may be incompatible. Executing files from
    untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative
    access.
    The "nodev" mount option causes the system to not interpret character or block special devices. Executing character
    or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain
    unauthorized administrative access.
    The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This
    option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing
    files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized
    administrative access.'
  desc 'rationale', ''
  desc 'check', 'Verify that the "nodev","nosuid", and "noexec" options are configured for /dev/shm:
    # cat /etc/fstab | grep /dev/shm
    tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
    If results are returned and the "nodev", "nosuid", or "noexec" options are missing, this is a finding.
    Verify "/dev/shm" is mounted with the "nodev", "nosuid", and "noexec" options:
    # mount | grep /dev/shm
    tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)
    If /dev/shm is mounted without secure options "nodev", "nosuid", and "noexec", this is a finding.'
  desc 'fix', 'Configure the system so that /dev/shm is mounted with the "nodev", "nosuid", and "noexec" options by
    adding /modifying the /etc/fstab with the following line:
    tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.3
  tag 'legacy': ['SV-95725', 'V-81013']
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000368-GPOS-00154'
  tag 'gid': 'V-204486'
  tag 'rid': 'SV-204486r603261_rule'
  tag 'stig_id': 'RHEL-07-021024'
  tag 'fix_id': 'F-4610r462553_fix'
  tag 'cci': ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag subsystems: ['etc_fstab', 'mount']
  tag 'host', 'container'

  if mount('/dev/shm').mounted?

    mount_file = etc_fstab.where { mount_point == '/dev/shm' }
    mount_command = mount('/dev/shm').file.mounted.stdout
                                     .match(/\((.*)\)/)[1].split(',')

    describe.one do
      describe '/etc/fstab mount options for /dev/shm' do
        subject { mount_file }
        its('mount_options.flatten') { should include 'nodev' }
        its('mount_options.flatten') { should include 'nosuid' }
        its('mount_options.flatten') { should include 'noexec' }
      end
      describe '/etc/fstab mount options for /dev/shm' do
        subject { mount_file }
        it { should_not exist }
      end
    end
    describe 'mount command options for /dev/shm' do
      subject { mount_command }
      it { should include 'nodev' }
      it { should include 'nosuid' }
      it { should include 'noexec' }
    end
  else
    describe mount('/dev/shm') do
      it { should_not be_mounted }
    end
  end
end
