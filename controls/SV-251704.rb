control 'SV-251704' do
  title 'The Red Hat Enterprise Linux operating system must not be configured to bypass password requirements for privilege escalation.'
  desc  "Without re-authentication, users may access resources or perform tasks for which they do not have authorization. \n\nWhen operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157',
                  'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-251704'
  tag rid: 'SV-251704r809568_rule'
  tag stig_id: 'RHEL-07-010344'
  tag fix_id: 'F-55095r809567_fix'
  tag cci: ['CCI-002038']
  tag legacy: []
  tag subsystems: ["sudo"]
  tag 'host'
  tag check: "Verify the operating system is not be configured to bypass password requirements for privilege escalation.\n\nCheck the configuration of the \"/etc/pam.d/sudo\" file with the following command:\n\n$ sudo grep pam_succeed_if /etc/pam.d/sudo\n\nIf any occurrences of \"pam_succeed_if\" is returned from the command, this is a finding."
  tag fix: "Configure the operating system to require users to supply a password for privilege escalation.\n\nCheck the configuration of the \"/etc/ pam.d/sudo\" file with the following command:\n$ sudo vi /etc/pam.d/sudo\n\nRemove any occurrences of \"pam_succeed_if\" in the file."

  if virtualization.system.eql?('docker') && !command("sudo").exist?
    impact 0.0
    describe "Control not applicable within a container without sudo enabled" do
      skip "Control not applicable within a container without sudo enabled"
    end
  else
    describe parse_config_file('/etc/pam.d/sudo') do
      its('content') { should_not match /pam_succeed_if/ }
    end
  end
end
