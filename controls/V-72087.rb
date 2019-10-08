# encoding: utf-8
#
control "V-72087" do
  title "The audit system must take appropriate action when the audit storage
volume is full."
  desc  "Taking appropriate action in case of a filled audit storage volume
will minimize the possibility of losing audit records."
  impact 0.5
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "gid": "V-72087"
  tag "rid": "SV-86711r2_rule"
  tag "stig_id": "RHEL-07-030320"
  tag "cci": ["CCI-001851"]
  tag "documentable": false
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd']
  desc "check", "Verify the action the operating system takes if the disk the audit
records are written to becomes full.

To determine the action that takes place if the disk is full on the remote
server, use the following command:

# grep -i disk_full_action /etc/audisp/audisp-remote.conf
disk_full_action = single

To determine the action that takes place if the network connection fails, use
the following command:

# grep -i network_failure_action /etc/audisp/audisp-remote.conf
network_failure_action = stop

If the value of the \"network_failure_action\" option is not \"syslog\",
\"single\", or \"halt\", or the line is commented out, this is a finding.

If the value of the \"disk_full_action\" option is not \"syslog\", \"single\",
or \"halt\", or the line is commented out, this is a finding."
  desc "fix", "Configure the action the operating system takes if the disk the
audit records are written to becomes full.

Uncomment or edit the \"disk_full_action\" option in
\"/etc/audisp/audisp-remote.conf\" and set it to \"syslog\", \"single\", or
\"halt\", such as the following line:

disk_full_action = single

Uncomment the \"network_failure_action\" option in
\"/etc/audisp/audisp-remote.conf\" and set it to \"syslog\", \"single\", or
\"halt\"."
  tag "fix_id": "F-78439r3_fix"

  describe parse_config_file('/etc/audisp/audisp-remote.conf') do
    its('disk_full_action.strip') { should match %r{^(syslog|single|halt)$} }
  end

# Test matches ./inspec-profiles/controls/V-73163.rb
  describe parse_config_file('/etc/audisp/audisp-remote.conf') do
    its('network_failure_action.strip') { should match %r{^(syslog|single|halt)$} }
  end
end
