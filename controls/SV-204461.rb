control 'SV-204461' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs)
    referenced in the /etc/passwd file are defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the GID is
    subsequently created, the user may have unintended rights to any files associated with the group.'
  desc 'rationale', ''
  desc 'check', 'Verify all GIDs referenced in the "/etc/passwd" file are defined in the "/etc/group" file.
    Check that all referenced GIDs exist with the following command:
    # pwck -r
    If GIDs referenced in "/etc/passwd" file are returned as not defined in "/etc/group" file, this is a finding.'
  desc 'fix', 'Configure the system to define all GIDs found in the "/etc/passwd" file by modifying the "/etc/group"
    file to add any non-existent group referenced in the "/etc/passwd" file, or change the GIDs referenced in the
    "/etc/passwd" file to a group that exists in "/etc/group".'
  impact 0.3
  tag 'legacy': ['V-72003', 'SV-86627']
  tag 'severity': 'low'
  tag 'gtitle': 'SRG-OS-000104-GPOS-00051'
  tag 'gid': 'V-204461'
  tag 'rid': 'SV-204461r603261_rule'
  tag 'stig_id': 'RHEL-07-020300'
  tag 'fix_id': 'F-4585r88576_fix'
  tag 'cci': ['CCI-000764']
  tag nist: ['IA-2']
  tag subsystems: ['accounts']
  tag 'host', 'container'

  describe 'All group identifiers in /etc/passwd' do
    it 'should be defined in /etc/groups' do
      expect(passwd.gids.map { |gid| gid.to_i }).to all(be_in(etc_group.gids)),
        "missing gids: #{passwd.gids.select { |gid| !etc_group.gids.include?(gid.to_i) }}"
    end
  end
end
