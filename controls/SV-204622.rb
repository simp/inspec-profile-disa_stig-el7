control 'SV-204622' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that remote X connections are disabled
    except to fulfill documented and validated mission requirements.'
  desc "The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack
    when the SSH client requests forwarding. A system administrator may have a stance in which they want to protect
    clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a ''no''
    setting.
    X11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host
    (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An
    attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also
    enabled.
    If X11 services are not required for the system's intended function, they should be disabled or restricted as
    appropriate to the system’s needs."
  desc 'rationale', ''
  desc 'check', 'Determine if X11Forwarding is disabled with the following command:
    # grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#"
    X11Forwarding no
    If the "X11Forwarding" keyword is set to "yes" and is not documented with the Information System Security Officer
    (ISSO) as an operational requirement or is missing, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11Forwarding" keyword and
    set its value to "no" (this file may be named differently or be in a different location if using a version of SSH
    that is provided by a third-party vendor):
    X11Forwarding no
    The SSH service must be restarted for changes to take effect:
    # systemctl restart sshd'
  impact 0.5
  tag 'legacy': ['SV-86927', 'V-72303']
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204622'
  tag 'rid': 'SV-204622r603849_rule'
  tag 'stig_id': 'RHEL-07-040710'
  tag 'fix_id': 'F-4746r622312_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('X11Forwarding') { should cmp 'no' }
    end
  end
end
