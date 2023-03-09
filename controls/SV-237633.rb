control 'SV-237633' do
  title 'The Red Hat Enterprise Linux operating system must restrict privilege elevation to authorized personnel.'
  desc  'The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the user for their password and confirms your request to execute a command by checking a file, called sudoers. If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag gid: 'V-237633'
  tag rid: 'SV-237633r646850_rule'
  tag stig_id: 'RHEL-07-010341'
  tag fix_id: 'F-40815r646849_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag subsystems: ['sudo']
  tag 'host'
  tag check: "Verify the \"sudoers\" file restricts sudo access to authorized personnel.\n$ sudo grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*\n\nIf the either of the following entries are returned, this is a finding:\nALL     ALL=(ALL) ALL\nALL     ALL=(ALL:ALL) ALL"
  tag fix: "Remove the following entries from the sudoers file:\nALL     ALL=(ALL) ALL\nALL     ALL=(ALL:ALL) ALL"

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    sudoers = command("grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*").stdout
    describe 'Sudoers file' do
      it 'should restrict access to privilege escalation' do
        expect(sudoers).not_to match(/ALL\s+ALL=\(ALL[:ALL]?\)\s+ALL/)
      end
    end
  end
end
