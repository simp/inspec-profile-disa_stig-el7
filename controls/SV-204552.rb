control 'SV-204552' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the mount command and syscall.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough
    information.
    At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization
    must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of
    compromise.
    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user
    sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals
    4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  tag 'legacy': ['V-72171', 'SV-86795']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the
    "mount" command and syscall occur.
    Check that the following system call is being audited by performing the following series of commands to check the
    file system rules in "/etc/audit/audit.rules":
    # grep -iw "mount" /etc/audit/audit.rules
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
    -a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=unset -k privileged-mount
    If both the "b32" and "b64" audit rules are not defined for the "mount" syscall, this is a finding.
    If all uses of the "mount" command are not being audited, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use
    the "mount" command and syscall occur.
    Add or update the following rules in "/etc/audit/rules.d/audit.rules":
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
    -a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=unset -k privileged-mount
    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000042-GPOS-00020'
  tag 'satisfies': ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172']
  tag 'gid': 'V-204552'
  tag 'rid': 'SV-204552r603261_rule'
  tag 'stig_id': 'RHEL-07-030740'
  tag 'fix_id': 'F-4676r462652_fix'
  tag 'cci': ['CCI-000135', 'CCI-002884']
  tag nist: ['AU-3 (1)', 'MA-4 (1) (a)']

  describe auditd.syscall('mount').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end

  if os.arch == 'x86_64'
    describe auditd.syscall('mount').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end

  describe auditd.path('/usr/bin/mount') do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
