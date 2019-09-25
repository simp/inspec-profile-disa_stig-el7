# encoding: utf-8
#
control "V-72079" do
  title "Auditing must be configured to produce records containing information
to establish what type of events occurred, where the events occurred, the
source of the events, and the outcome of the events.

These audit records must also identify individual identities of group account
users."
  desc  "
    Without establishing what type of events occurred, it would be difficult to
establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the operating system audit
logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
operating system.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000038-GPOS-00016"
  tag "satisfies": ["SRG-OS-000038-GPOS-00016", "SRG-OS-000039-GPOS-00017",
"SRG-OS-000042-GPOS-00021", "SRG-OS-000254-GPOS-00095",
"SRG-OS-000255-GPOS-00096"]
  tag "gid": "V-72079"
  tag "rid": "SV-86703r2_rule"
  tag "stig_id": "RHEL-07-030000"
  tag "cci": ["CCI-000126", "CCI-000131"]
  tag "documentable": false
  tag "nist": ["AU-2 d", "AU-3", "Rev_4"]
  tag "subsystems": ['audit', 'auditd']
  tag "check": "Verify the operating system produces audit records containing
information to establish when (date and time) the events occurred.

Check to see if auditing is active by issuing the following command:

# systemctl is-active auditd.service
Active: active (running) since Tue 2015-01-27 19:41:23 EST; 22h ago

If the \"auditd\" status is not active, this is a finding."
  tag "fix": "Configure the operating system to produce audit records
containing information to establish when (date and time) the events occurred.

Enable the auditd service with the following command:

# systemctl start auditd.service"
  tag "fix_id": "F-78431r2_fix"

  describe service('auditd') do
    it { should be_running }
  end
end
