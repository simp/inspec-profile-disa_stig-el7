control 'SV-204471' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all files and directories
    contained in local interactive user home directories have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User
    Identifier "UID" as the UID of the un-owned files.'
  desc 'rationale', ''
  desc 'check', %q(Verify all files and directories in a local interactive user's home directory have a valid owner.
    Check the owner of all files and directories in a local interactive user's home directory with the following
    command:
    Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".
    $ sudo ls -lLR /home/smithj
    -rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
    -rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
    -rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3
    If any files or directories are found without an owner, this is a finding.)
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a
    valid user to all unowned files and directories on RHEL 7 with the "chown" command:
    Note: The example will be for the user smithj, who has a home directory of "/home/smithj".
    $ sudo chown smithj /home/smithj/<file or directory>'
  impact 0.5
  tag 'legacy': ['SV-86647', 'V-72023']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204471'
  tag 'rid': 'SV-204471r744105_rule'
  tag 'stig_id': 'RHEL-07-020660'
  tag 'fix_id': 'F-4595r744104_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['home_dirs']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else

    exempt_home_users = input('exempt_home_users')
    non_interactive_shells = input('non_interactive_shells')

    ignore_shells = non_interactive_shells.join('|')

    uid_min = login_defs.read_params['UID_MIN'].to_i
    uid_min = 1000 if uid_min.nil?

    findings = Set[]
    users.where do
      !shell.match(ignore_shells) && (uid >= uid_min || uid == 0)
    end.entries.each do |user_info|
      next if exempt_home_users.include?(user_info.username.to_s)

      findings += command("find #{user_info.home} -xdev -xautofs -not -user #{user_info.username}").stdout.split("\n")
    end
    describe 'Files and directories that are not owned by the user' do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end
