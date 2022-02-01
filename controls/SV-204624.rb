control 'SV-204624' do
  title 'The Red Hat Enterprise Linux operating system must not have a graphical display manager installed unless
    approved.'
  desc 'Internet services that are not required for system or application processes must not be active to decrease
    the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and
    must not be used unless approved and documented.'
  tag 'legacy': ['SV-86931', 'V-72307']
  desc 'rationale', ''
  desc 'check', 'Verify the system is configured to boot to the command line:
    $ systemctl get-default
    multi-user.target
    If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO)
    lacks a documented requirement for a graphical user interface, this is a finding.
    Verify a graphical user interface is not installed:
    $ rpm -qa | grep xorg | grep server
    Ask the System Administrator if use of a graphical user interface is an operational requirement.
    If the use of a graphical user interface on the system is not documented with the ISSO, this is a finding.
    '
  desc 'fix', 'Document the requirement for a graphical user interface with the ISSO or reinstall the operating
    system without the graphical user interface. If reinstallation is not feasible, then continue with the following
    procedure:
    Open an SSH session and enter the following commands:
    $ sudo systemctl set-default multi-user.target
    $ sudo yum remove xorg-x11-server-Xorg xorg-x11-server-common xorg-x11-server-utils
    A reboot is required for the changes to take effect.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204624'
  tag 'rid': 'SV-204624r646847_rule'
  tag 'stig_id': 'RHEL-07-040730'
  tag 'fix_id': 'F-36316r646846_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  x11_enabled = input('x11_enabled')

  unless x11_enabled
    describe package('xorg-x11-server-common') do
      it { should_not be_installed }
    end
  end

  if x11_enabled
    describe package('xorg-x11-server-common') do
      it { should be_installed }
    end
  end
end
