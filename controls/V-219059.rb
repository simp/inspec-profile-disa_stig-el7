control 'V-219059' do
  title 'The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless
    required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating
    malicious activity.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000114-GPOS-00059'
  tag 'satisfies': %w(SRG-OS-000114-GPOS-00059 SRG-OS-000378-GPOS-00163 SRG-OS-000480-GPOS-00227)
  tag 'gid': 'V-219059'
  tag 'rid': 'SV-219059r603261_rule'
  tag 'stig_id': 'RHEL-07-020111'
  tag 'fix_id': 'F-36318r602663_fix'
  tag 'cci': %w(CCI-001958 CCI-000778 CCI-000366)
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': nil
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': nil
  tag 'check': 'Note: If the operating system does not have a graphical user interface installed, this requirement
    is Not Applicable.
    Verify the operating system disables the ability to automount devices in a graphical user interface.
    Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This
    path must be modified if a database other than "local" is being used.
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
  tag 'fix': 'Configure the graphical user interface to disable the ability to automount devices.
    Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This
    path must be modified if a database other than "local" is being used.
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
end
