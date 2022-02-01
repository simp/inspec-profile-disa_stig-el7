control 'SV-219059' do
  title 'The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required.'
  desc  'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-219059'
  tag rid: 'SV-219059r603261_rule'
  tag stig_id: 'RHEL-07-020111'
  tag fix_id: 'F-36318r602663_fix'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag legacy: ['V-100023', 'SV-109127']
  tag false_negatives: ''
  tag false_positives: ''
  tag documentable: false
  tag mitigations: ''
  tag severity_override_guidance: ''
  tag potential_impacts: ''
  tag third_party_tools: ''
  tag mitigation_controls: ''
  tag responsibility: ''
  tag ia_controls: ''
  tag check: "Note: If the operating system does not have a graphical user interface installed, this requirement is Not Applicable.\n\nVerify the operating system disables the ability to automount devices in a graphical user interface.\n\nNote: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.\n\nCheck to see if automounter service is disabled with the following commands:\n# cat /etc/dconf/db/local.d/00-No-Automount\n\n[org/gnome/desktop/media-handling]\n\nautomount=false\n\nautomount-open=false\n\nautorun-never=true\n\nIf the output does not match the example above, this is a finding.\n\n# cat /etc/dconf/db/local.d/locks/00-No-Automount\n\n/org/gnome/desktop/media-handling/automount\n\n/org/gnome/desktop/media-handling/automount-open\n\n/org/gnome/desktop/media-handling/autorun-never\n\nIf the output does not match the example, this is a finding."
  tag fix: "Configure the graphical user interface to disable the ability to automount devices.\n\nNote: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.\n\nCreate or edit the /etc/dconf/db/local.d/00-No-Automount file and add the following:  \n\n[org/gnome/desktop/media-handling]\n\nautomount=false\n\nautomount-open=false\n\nautorun-never=true\n\nCreate or edit the /etc/dconf/db/local.d/locks/00-No-Automount file and add the following:\n/org/gnome/desktop/media-handling/automount\n\n/org/gnome/desktop/media-handling/automount-open\n\n/org/gnome/desktop/media-handling/autorun-never\n\nRun the following command to update the database:\n\n# dconf update"
end
