control 'SV-204513' do
  title 'The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator
    (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches
    75% of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they
    are unable to plan for audit record storage capacity expansion.'
  tag 'legacy': ['V-72089', 'SV-86713']
  desc 'rationale', ''
  desc 'check', 'Verify the operating system initiates an action to notify the SA and ISSO (at a minimum) when
    allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
    Check the system configuration to determine the partition the audit records are being written to with the following
    command:
    $ sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log
    Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record
    storage capacity is reached:
    $ sudo grep -iw space_left /etc/audit/auditd.conf
    space_left = 25%
    If the value of the "space_left" keyword is not set to 25 percent of the total partition size, this is a finding.'
  desc 'fix', 'Configure the operating system to initiate an action to notify the SA and ISSO (at a minimum) when
    allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
    Set the value of the "space_left" keyword in "/etc/audit/auditd.conf" to 25 percent of the partition size.
    space_left = 25%
    Reload the auditd daemon to apply changes made to the "/etc/audit/auditd.conf" file.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000343-GPOS-00134'
  tag 'gid': 'V-204513'
  tag 'rid': 'SV-204513r744112_rule'
  tag 'stig_id': 'RHEL-07-030330'
  tag 'fix_id': 'F-4637r744111_fix'
  tag 'cci': ['CCI-001855']
  tag nist: ['AU-5 (1)']

  if (f = file(audit_log_dir = command("dirname #{auditd_conf.log_file}").stdout.strip)).directory?
    # Fetch partition sizes in 1K blocks for consistency
    partition_info = command("df -B 1K #{audit_log_dir}").stdout.split("\n")
    partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split(' ')

    # Get partition size
    partition_sz = partition_sz_arr[1]

    # Convert to MB and get 25%
    exp_space_left = partition_sz.to_i / 1024 / 4

    describe auditd_conf do
      its('space_left.to_i') { should be >= exp_space_left }
    end
  else
    describe f.directory? do
      it { should be true }
    end
  end
end
