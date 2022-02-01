control 'SV-237634' do
  title "The Red Hat Enterprise Linux operating system must use the invoking user's password for privilege escalation when using \"sudo\"."
  desc  "The sudoers security policy requires that users authenticate themselves before they can use sudo. When sudoers requires authentication, it validates the invoking user's credentials. If the rootpw, targetpw, or runaspw flags are defined and not disabled, by default the operating system will prompt the invoking user for the \"root\" user password. \nFor more information on each of the listed configurations, reference the sudoers(5) manual page."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag gid: 'V-237634'
  tag rid: 'SV-237634r809213_rule'
  tag stig_id: 'RHEL-07-010342'
  tag fix_id: 'F-40816r646852_fix'
  tag cci: ['CCI-002227']
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
  tag check: "Verify that the sudoers security policy is configured to use the invoking user's password for privilege escalation.\n\n$ sudo egrep -i '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/* | grep -v '#'\n\n/etc/sudoers:Defaults !targetpw\n/etc/sudoers:Defaults !rootpw\n/etc/sudoers:Defaults !runaspw\n\nIf no results are returned, this is a finding.\nIf results are returned from more than one file location, this is a finding.\nIf \"Defaults !targetpw\" is not defined, this is a finding.\nIf \"Defaults !rootpw\" is not defined, this is a finding.\nIf \"Defaults !runaspw\" is not defined, this is a finding."
  tag fix: "Define the following in the Defaults section of the /etc/sudoers file or a configuration file in the /etc/sudoers.d/ directory:\nDefaults !targetpw\nDefaults !rootpw\nDefaults !runaspw"
end
