control 'SV-251702' do
  title 'The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords.'
  desc  'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag gid: 'V-251702'
  tag rid: 'SV-251702r809220_rule'
  tag stig_id: 'RHEL-07-010291'
  tag fix_id: 'F-55093r809219_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
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
  tag check: "Check the \"/etc/shadow\" file for blank passwords with the following command:\n\n$ sudo awk -F: '!$2 {print $1}' /etc/shadow\n\nIf the command returns any results, this is a finding."
  tag fix: "Configure all accounts on the system to have a password or lock the account with the following commands:\n\nPerform a password reset:\n$ sudo passwd [username]\nLock an account:\n$ sudo passwd -l [username]"
end
