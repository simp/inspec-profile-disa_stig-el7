# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

control "V-72193" do
  title "All uses of the `rmmod` command must be audited."
  desc  "Without generating audit records that are specific to the security and mission
        needs of the organization, it would be difficult to establish, correlate, and
        investigate the events relating to an incident or identify those responsible for one.

        Audit records can be generated from various components within the information
        system (e.g., module or policy filter)."

  impact 0.5

  tag "gtitle": "SRG-OS-000471-GPOS-00216"
  tag "gid": "V-72193"
  tag "rid": "SV-86817r2_rule"
  tag "stig_id": "RHEL-07-030850"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "check": "Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"rmmod\" command occur.

Check the auditing rules in \"/etc/audit/audit.rules\" with the following command:

# grep -i rmmod /etc/audit/audit.rules

If the command does not return the following output (appropriate to the
architecture), this is a finding.

-w /sbin/rmmod -p x -F auid!=4294967295 -k module-change

If the command does not return any output, this is a finding."
  tag "fix": "Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"rmmod\" command occur.

Add or update the following rule in \"/etc/audit/rules.d/audit.rules\" (removing
those that do not match the CPU architecture):

-w /sbin/rmmod -p x -F auid!=4294967295 -k module-change

The audit daemon must be restarted for the changes to take effect."

  @audit_file = '/sbin/rmmod'

  describe auditd.file(@audit_file) do
    its('permissions') { should_not cmp [] }
    its('action') { should_not include 'never' }
  end

  # Resource creates data structure including all usages of file
  @perms = auditd.file(@audit_file).permissions

  @perms.each do |perm|
    describe perm do
      it { should include 'x' }
    end
  end
  only_if { file(@audit_file).exist? }
end
