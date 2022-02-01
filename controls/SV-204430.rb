control 'SV-204430' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that users must re-authenticate for
    privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have
    authorization.
    When operating systems provide the capability to escalate a functional capability, it is critical the user
    reauthenticate.'
  tag 'legacy': ['V-71949', 'SV-86573']
  tag 'rationale': ''
  tag 'check': 'Verify the operating system requires users to reauthenticate for privilege escalation.
    Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:
    # grep -i authenticate /etc/sudoers /etc/sudoers.d/*
    If any uncommented line is found with a "!authenticate" tag, this is a finding.'
  tag 'fix': 'Configure the operating system to require users to reauthenticate for privilege escalation.
    Check the configuration of the "/etc/sudoers" file with the following command:
    # visudo
    Remove any occurrences of "!authenticate" tags in the file.
    Check the configuration of the "/etc/sudoers.d/*" files with the following command:
    # grep -i authenticate /etc/sudoers /etc/sudoers.d/*
    Remove any occurrences of "!authenticate" tags in the file(s).'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000373-GPOS-00156'
  tag 'satisfies': ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'gid': 'V-204430'
  tag 'rid': 'SV-204430r603261_rule'
  tag 'stig_id': 'RHEL-07-010350'
  tag 'fix_id': 'F-4554r88483_fix'
  tag 'cci': ['CCI-002038']
  tag nist: ['IA-11']

  describe command('grep -ir authenticate /etc/sudoers /etc/sudoers.d/*') do
    its('stdout') { should_not match(/!authenticate/) }
  end
end
