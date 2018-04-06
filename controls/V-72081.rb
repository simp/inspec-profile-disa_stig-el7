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

MONITOR_KERNEL_LOG = attribute(
  'monitor_kernel_log',
  description: 'Set this to false if your system availability concern is not documented or
  there is no monitoring of the kernel log',
  default: true
)

control "V-72081" do
  title "The operating system must shut down upon audit processing failure, unless
availability is an overriding concern. If availability is a concern, the system must
alert the designated staff (System Administrator [SA] and Information System
Security Officer [ISSO] at a minimum) in the event of an audit processing failure."
  desc  "
    It is critical for the appropriate personnel to be aware if a system is at risk
of failing to process audit logs as required. Without this notification, the
security personnel may be unaware of an impending failure of the audit capability,
and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or exceeded.

    This requirement applies to each audit data storage repository (i.e., distinct
information system component where audit records are stored), the centralized audit
storage capacity of organizations (i.e., all audit data storage repositories
combined), or both."

if auditd.status['failure'].nil?
  impact 0.7
elsif auditd.status['failure'].match?(%r{1|2})
  impact 0.5
elsif auditd.status['failure'].eql?(1) && !MONITOR_KERNEL_LOG
  impact 0.3
else
   impact 0.5
 end

  tag "gtitle": "SRG-OS-000046-GPOS-00022"
  tag "gid": "V-72081"
  tag "rid": "SV-86705r1_rule"
  tag "stig_id": "RHEL-07-030010"
  tag "cci": "CCI-000139"
  tag "nist": ["AU-5 a", "Rev_4"]
  tag "subsystems": ['audit', 'auditd']
  tag "check": "Confirm the audit configuration regarding how auditing processing
failures are handled.

Check to see what level \"auditctl\" is set to with following command:

# auditctl -l | grep /-f
 -f 2

If the value of \"-f\" is set to \"2\", the system is configured to panic (shut
down) in the event of an auditing failure.

If the value of \"-f\" is set to \"1\", the system is configured to only send
information to the kernel log regarding the failure.

If the \"-f\" flag is not set, this is a CAT I finding.

If the \"-f\" flag is set to any value other than \"1\" or \"2\", this is a CAT II
finding.

If the \"-f\" flag is set to \"1\" but the availability concern is not documented or
there is no monitoring of the kernel log, this is a CAT III finding."

  tag "fix": "Configure the operating system to shut down in the event of an audit
processing failure.

Add or correct the option to shut down the operating system with the following
command:

# auditctl -f 2

If availability has been determined to be more important, and this decision is
documented with the ISSO, configure the operating system to notify system
administration staff and ISSO staff in the event of an audit processing failure with
the following command:

# auditctl -f 1

Kernel log monitoring must also be configured to properly alert designated staff.

The audit daemon must be restarted for the changes to take effect."

  describe auditd.status['failure'] do
    it { should match %r{^(1|2)$} }
  end
end
