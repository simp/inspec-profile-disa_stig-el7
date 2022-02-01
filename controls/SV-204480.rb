control 'SV-204480' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that file systems containing user home
    directories are mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges.
    This option must be used for mounting any file system not containing approved setuid and setguid files. Executing
    files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized
    administrative access.'
  tag 'legacy': ['SV-86665', 'V-72041']
  desc 'rationale', ''
  desc 'check', %q{Verify file systems that contain user home directories are mounted with the "nosuid" option.
    Find the file system(s) that contain the user home directories with the following command:
    Note: If a separate file system has not been created for the user home directories (user home directories are
    mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.
    # awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
    smithj 1001 /home/smithj
    thomasr 1002 /home/thomasr
    Check the file systems that are mounted at boot time with the following command:
    # more /etc/fstab
    UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4   rw,relatime,discard,data=ordered,nosuid 0 2
    If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the
    "nosuid" option set, this is a finding.}
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that contain user home
    directories.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204480'
  tag 'rid': 'SV-204480r603838_rule'
  tag 'stig_id': 'RHEL-07-021000'
  tag 'fix_id': 'F-4604r88633_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  describe mount('/home') do
    its('options') { should include 'nosuid' }
  end
end
