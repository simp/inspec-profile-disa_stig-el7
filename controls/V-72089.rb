# encoding: utf-8
#
control "V-72089" do
  title "The operating system must immediately notify the System Administrator
(SA) and Information System Security Officer ISSO (at a minimum) when allocated
audit record storage volume reaches 75% of the repository maximum audit record
storage capacity."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75 percent utilization, they are unable to plan for audit record
storage capacity expansion."
  impact 0.5
  tag "gtitle": "SRG-OS-000343-GPOS-00134"
  tag "gid": "V-72089"
  tag "rid": "SV-86713r1_rule"
  tag "stig_id": "RHEL-07-030330"
  tag "cci": ["CCI-001855"]
  tag "documentable": false
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "subsystems": ['auditd']
  desc "check", "Verify the operating system immediately notifies the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches 75
percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are
being written to with the following command:

# grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the
example being \"/var/log/audit/\"):

# df -h /var/log/audit/
0.9G /var/log/audit

If the audit records are not being written to a partition specifically created
for audit records (in this example \"/var/log/audit\" is a separate partition),
determine the amount of space other files in the partition are currently
occupying with the following command:

# du -sh <partition>
1.8G /var

Determine what the threshold is for the system to take action when 75 percent
of the repository maximum audit record storage capacity is reached:

# grep -i space_left /etc/audit/auditd.conf
space_left = 225

If the value of the \"space_left\" keyword is not set to 25 percent of the
total partition size, this is a finding."
  desc "fix", "Configure the operating system to immediately notify the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches 75
percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are
being written to:

# grep log_file /etc/audit/auditd.conf

Determine the size of the partition that audit records are written to (with the
example being \"/var/log/audit/\"):

# df -h /var/log/audit/

Set the value of the \"space_left\" keyword in \"/etc/audit/auditd.conf\" to 75
percent of the partition size."
  tag "fix_id": "F-78441r1_fix"

  describe auditd_conf do
    before(:all) do
      @audit_log_dir = File.dirname(auditd_conf.log_file)

      if file(@audit_log_dir).directory?
        partition_info = command("df -h #{@audit_log_dir}").stdout.split("\n")

        partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split(" ")

        # Get partition size in GB
        partition_sz = partition_sz_arr[1].gsub(/G/, '')

        # Convert to MB and get 25%
        @exp_space_left = partition_sz.to_i * 1024 / 4
      end
    end

    it 'should have an audit log directory' do
      expect(file(@audit_log_dir).directory?).to be true
    end

    its('space_left.to_i') { should be >= @exp_space_left }
  end
end
