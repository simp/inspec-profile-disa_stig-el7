control 'SV-204504' do
  title 'The Red Hat Enterprise Linux operating system must shut down upon audit processing failure, unless
    availability is an overriding concern. If availability is a concern, the system must alert the designated staff
    (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit
    processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit
    logs as required. Without this notification, the security personnel may be unaware of an impending failure of the
    audit capability, and system operation may be adversely affected.
    Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit
    storage capacity being reached or exceeded.
    This requirement applies to each audit data storage repository (i.e., distinct information system component where
    audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage
    repositories combined), or both.'
  tag 'legacy': ['V-72081', 'SV-86705']
  desc 'rationale', ''
  desc 'check', 'Confirm the audit configuration regarding how auditing processing failures are handled.
    Check to see what level "auditctl" is set to with following command:
    # auditctl -s | grep -i "fail"
    failure 2
    Note: If the value of "failure" is set to "2", the system is configured to panic (shut down) in the event of an
    auditing failure. If the value of "failure" is set to "1", the system is configured to only send information to the
    kernel log regarding the failure.
    If the "failure" setting is set to any value other than "1" or "2", this is a finding.
    If the "failure" setting is not set, this should be upgraded to a CAT I finding.
    If the "failure" setting is set to "1" but the availability concern is not documented or there is no monitoring of
    the kernel log, this should be downgraded to a CAT III finding.'
  desc 'fix', 'Configure the operating system to shut down in the event of an audit processing failure.
    Add or correct the option to shut down the operating system with the following command:
    # auditctl -f 2
    Edit the "/etc/audit/rules.d/audit.rules" file and add the following line:
    -f 2
    If availability has been determined to be more important, and this decision is documented with the ISSO, configure
    the operating system to notify system administration staff and ISSO staff in the event of an audit processing
    failure with the following command:
    # auditctl -f 1
    Edit the "/etc/audit/rules.d/audit.rules" file and add the following line:
    -f 1
    Kernel log monitoring must also be configured to properly alert designated staff.
    The audit daemon must be restarted for the changes to take effect.'
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000046-GPOS-00022'
  tag 'satisfies': ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000047-GPOS-00023']
  tag 'gid': 'V-204504'
  tag 'rid': 'SV-204504r603261_rule'
  tag 'stig_id': 'RHEL-07-030010'
  tag 'fix_id': 'F-4628r462467_fix'
  tag 'cci': ['CCI-000139']
  tag nist: ['AU-5 a']

  monitor_kernel_log = input('monitor_kernel_log')

  if auditd.status['failure'].nil?
    impact 0.5
  elsif auditd.status['failure'].match?(/^1$/) && !monitor_kernel_log
    impact 0.3
  else
    impact 0.5
  end

  if !monitor_kernel_log
    describe auditd.status['failure'] do
      it { should match(/^2$/) }
    end
  else
    describe auditd.status['failure'] do
      it { should match(/^(1|2)$/) }
    end
  end
end
