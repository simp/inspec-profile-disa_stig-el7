control 'SV-237635' do
  title 'The Red Hat Enterprise Linux operating system must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*
/etc/sudoers:Defaults timestamp_timeout=0

If results are returned from more than one file location, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require re-authentication.
Edit the /etc/sudoers file:
$ sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=[value]
Note: The "[value]" must be a number that is greater than or equal to "0".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: nil
  tag gid: 'V-237635'
  tag rid: 'SV-237635r809215_rule'
  tag stig_id: 'RHEL-07-010343'
  tag fix_id: 'F-40817r646855_fix'
  tag cci: ['CCI-002038']
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
    describe command("grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*").stdout.strip do
      it { should match /^[^#].*Defaults timestamp_timeout=\d/ }
      it { should_not match /\n/ }
    end
  end
end
