control 'SV-237635' do
  title 'The Red Hat Enterprise Linux operating system must require re-authentication when using the "sudo" command.'
  desc  "Without re-authentication, users may access resources or perform tasks for which they do not have authorization. \n\nWhen operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the \"sudo\" command.\n\nIf the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: nil
  tag gid: 'V-237635'
  tag rid: 'SV-237635r809215_rule'
  tag stig_id: 'RHEL-07-010343'
  tag fix_id: 'F-40817r646855_fix'
  tag cci: ['CCI-002038']
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
  tag check: "Verify the operating system requires re-authentication when using the \"sudo\" command to elevate privileges.\n\n$ sudo grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*\n/etc/sudoers:Defaults timestamp_timeout=0\n\nIf results are returned from more than one file location, this is a finding.\n\nIf \"timestamp_timeout\" is set to a negative number, is commented out, or no results are returned, this is a finding."
  tag fix: "Configure the \"sudo\" command to require re-authentication.\nEdit the /etc/sudoers file:\n$ sudo visudo\n\nAdd or modify the following line:\nDefaults timestamp_timeout=[value]\nNote: The \"[value]\" must be a number that is greater than or equal to \"0\"."
end
