control 'V-228564' do
  title 'The Red Hat Enterprise Linux operating system must protect audit information from unauthorized read,
    modification, or deletion.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of
    potentially malicious system activity is impossible to achieve.
    To ensure the veracity of audit information, the operating system must protect audit information from unauthorized
    modification.
    Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to
    successfully audit information system activity.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000057-GPOS-00027'
  tag 'satisfies': %w(SRG-OS-000057-GPOS-00027
                      SRG-OS-000058-GPOS-00028
                      SRG-OS-000059-GPOS-00029
                      SRG-OS-000206-GPOS-00084)
  tag 'gid': 'V-228564'
  tag 'rid': 'SV-228564r606407_rule'
  tag 'stig_id': 'RHEL-07-910055'
  tag 'fix_id': 'F-23603r419770_fix'
  tag 'cci': %w(CCI-001314 CCI-000162 CCI-000163 CCI-000164)
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
  tag 'check': 'Verify the operating system audit records have proper permissions and ownership.
    List the full permissions and ownership of the audit log files with the following command.
    # ls -la /var/log/audit
    total 4512
    drwx------. 2 root root 23 Apr 25 16:53 .
    drwxr-xr-x. 17 root root 4096 Aug 9 13:09 ..
    -rw-------. 1 root root 8675309 Aug 9 12:54 audit.log
    Audit logs must be mode 0600 or less permissive.
    If any are more permissive, this is a finding.
    The owner and group owner of all audit log files must both be "root". If any other owner or group owner is listed,
    this is a finding.'
  tag 'fix': 'Change the mode of the audit log files with the following command:
    # chmod 0600 [audit_file]
    Change the owner and group owner of the audit log files with the following command:
    # chown root:root [audit_file]'
end
