control 'SV-219059' do
  title 'The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Note: If the operating system does not have a graphical user interface installed, this requirement is Not Applicable.

Verify the operating system disables the ability to automount devices in a graphical user interface.

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

Check to see if automounter service is disabled with the following commands:
# cat /etc/dconf/db/local.d/00-No-Automount

[org/gnome/desktop/media-handling]

automount=false

automount-open=false

autorun-never=true

If the output does not match the example above, this is a finding.

# cat /etc/dconf/db/local.d/locks/00-No-Automount

/org/gnome/desktop/media-handling/automount

/org/gnome/desktop/media-handling/automount-open

/org/gnome/desktop/media-handling/autorun-never

If the output does not match the example, this is a finding.'
  desc 'fix', 'Configure the graphical user interface to disable the ability to automount devices.

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

Create or edit the /etc/dconf/db/local.d/00-No-Automount file and add the following:  

[org/gnome/desktop/media-handling]

automount=false

automount-open=false

autorun-never=true

Create or edit the /etc/dconf/db/local.d/locks/00-No-Automount file and add the following:
/org/gnome/desktop/media-handling/automount

/org/gnome/desktop/media-handling/automount-open

/org/gnome/desktop/media-handling/autorun-never

Run the following command to update the database:

# dconf update'
  impact 0.0
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-219059'
  tag rid: 'SV-219059r603261_rule'
  tag stig_id: 'RHEL-07-020111'
  tag fix_id: 'F-36318r602663_fix'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag legacy: ['V-100023', 'SV-109127']
  tag check: nil
  tag fix: nil
  tag subsystems: ['gui', 'automount']
  tag host: nil

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif package('gnome-desktop3').installed?
    options = {
        assignment_regex: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/
      }

    describe parse_config_file(input('automount_config'), options) do
      its('automount') { should cmp 'false' }
      its('automount-open') { should cmp 'false' }
      its('autorun-never') { should cmp 'true' }
    end
    describe file(input('automount_locks_config')) do
      its('content') { should match /automount$/ }
      its('content') { should match /automount-open$/ }
      its('content') { should match /autorun-never$/ }
    end

  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
