control 'SV-228564' do
  title 'The Red Hat Enterprise Linux operating system must protect audit information from unauthorized read, modification, or deletion.'
  desc  "If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.\n\nTo ensure the veracity of audit information, the operating system must protect audit information from unauthorized modification.\n\nAudit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029',
                  'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-228564'
  tag rid: 'SV-228564r606407_rule'
  tag stig_id: 'RHEL-07-910055'
  tag fix_id: 'F-23603r419770_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
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
  tag check: "Verify the operating system audit records have proper permissions and ownership.\n\nList the full permissions and ownership of the audit log files with the following command.\n\n# ls -la /var/log/audit \ntotal 4512\ndrwx------. 2 root root 23 Apr 25 16:53 .\ndrwxr-xr-x. 17 root root 4096 Aug 9 13:09 ..\n-rw-------. 1 root root 8675309 Aug 9 12:54 audit.log\n\nAudit logs must be mode 0600 or less permissive. \nIf any are more permissive, this is a finding.\n\nThe owner and group owner of all audit log files must both be \"root\". If any other owner or group owner is listed, this is a finding."
  tag fix: "Change the mode of the audit log files with the following command: \n\n# chmod 0600 [audit_file]\n\nChange the owner and group owner of the audit log files with the following command: \n\n# chown root:root [audit_file]"
end
