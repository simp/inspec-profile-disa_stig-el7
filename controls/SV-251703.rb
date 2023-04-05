control 'SV-251703' do
  title 'The Red Hat Enterprise Linux operating system must specify the default "include" directory for the /etc/sudoers file.'
  desc 'The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.

It is possible to include other sudoers files from within the sudoers file currently being parsed using the #include and #includedir directives. When sudo reaches this line it will suspend processing of the current file (/etc/sudoers) and switch to the specified file/directory. Once the end of the included file(s) is reached, the rest of /etc/sudoers will be processed. Files that are included may themselves include other files. A hard limit of 128 nested include files is enforced to prevent include file loops.'
  desc 'check', 'Verify the operating system specifies only the default "include" directory for the /etc/sudoers file with the following command:

$ sudo grep include /etc/sudoers

#includedir /etc/sudoers.d

If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding.

Verify the operating system does not have nested "include" files or directories within the /etc/sudoers.d directory with the following command:

$ sudo grep include /etc/sudoers.d/*

If results are returned, this is a finding.'
  desc 'fix', 'Configure the /etc/sudoers file to only include the /etc/sudoers.d directory.

Edit the /etc/sudoers file with the following command:

$ sudo visudo

Add or modify the following line:
#includedir /etc/sudoers.d'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag gid: 'V-251703'
  tag rid: 'SV-251703r809566_rule'
  tag stig_id: 'RHEL-07-010339'
  tag fix_id: 'F-55094r809222_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag subsystems: ['sudo']
  tag host: nil
  tag check: nil
  tag fix: nil

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    options = {
      assignment_regex: /^(#includedirs?)\s*(.*?)\s*$/
    }
    describe parse_config_file('/etc/sudoers', options) do
      its('#includedirs') { should cmp '/etc/sudoers.d' }
    end
    describe command('grep include /etc/sudoers.d') do
      its('stdout') { should be_empty }
    end
  end
end
