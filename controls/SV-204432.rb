control 'SV-204432' do
  title 'The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system
    via a graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  tag 'legacy': ['V-71953', 'SV-86577']
  tag 'rationale': ''
  tag 'check': 'Verify the operating system does not allow an unattended or automatic logon to the system via a
    graphical user interface.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:
    # grep -i automaticloginenable /etc/gdm/custom.conf
    AutomaticLoginEnable=false
    If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  tag 'fix': 'Configure the operating system to not allow an unattended or automatic logon to the system via a
    graphical user interface.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf"
    file to "false":
    [daemon]
    AutomaticLoginEnable=false'
  impact 0.7
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00229'
  tag 'gid': 'V-204432'
  tag 'rid': 'SV-204432r603261_rule'
  tag 'stig_id': 'RHEL-07-010440'
  tag 'fix_id': 'F-4556r88489_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  custom_conf = '/etc/gdm/custom.conf'

  if package('gdm').installed?
    if (f = file(custom_conf)).exist?
      describe ini(custom_conf) do
        its('daemon.AutomaticLoginEnable') { cmp false }
      end
    else
      describe f do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'The system does not have GDM installed' do
      skip 'The system does not have GDM installed, this requirement is Not Applicable.'
    end
  end
end
