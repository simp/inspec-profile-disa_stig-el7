control 'SV-204479' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all system device files are
    correctly labeled to prevent unauthorized modification.'
  desc 'If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system
    may perform unintended or unauthorized operations.'
  desc 'rationale', ''
  desc 'check', %q{Verify that all system device files are correctly labeled to prevent unauthorized modification.
    List all device files on the system that are incorrectly labeled with the following commands:
    Note: Device files are normally found under "/dev", but applications may place device files in other directories and
    may necessitate a search of the entire system.
    #find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"
    #find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"
    Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual
    machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device
    files are not a finding.
    If there is output from either of these commands, other than already noted, this is a finding.}
  desc  'fix', "
    Run the following command to determine which package owns the device file:

    # rpm -qf <filename>

    The package can be reinstalled from a yum repository using the command:

    # sudo yum reinstall <packagename>

    Alternatively, the package can be reinstalled from trusted media using the
command:

    # sudo rpm -Uvh <packagename>
  "
  impact 0.5
  tag 'legacy': ['SV-86663', 'V-72039']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204479'
  tag 'rid': 'SV-204479r603261_rule'
  tag 'stig_id': 'RHEL-07-020900'
  tag 'fix_id': 'F-4603r88630_fix'
  tag 'cci': ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813',
              'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1)', 'CM-5 (1)']
  tag subsystems: ['system_device', 'device_files']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    virtual_machine = input('virtual_machine')

    findings = Set[]
    findings += command('find / -xdev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"').stdout.split("\n")
    findings += command('find / -xdev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"').stdout.split("\n")
    findings += command('find / -xdev -context *:vmci_device_t:* \( -type c -o -type b \) -printf "%p %Z\n"').stdout.split("\n")

    describe findings do
      if virtual_machine
        its('length') { should cmp 1 }
        its('first') { should include '/dev/vmci' }
      else
        its('length') { should cmp 0 }
      end
    end
  end
end
