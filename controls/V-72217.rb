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

control "V-72217" do
  title "The operating system must limit the number of concurrent sessions to 10 for
all accounts and/or account types."
  desc  "
    Operating system management includes the ability to control the number of users
and user sessions that utilize an operating system. Limiting the number of allowed
users and sessions per user is helpful in reducing the risks related to DoS attacks.

    This requirement addresses concurrent sessions for information system accounts
and does not address concurrent sessions by single users via multiple system
accounts. The maximum number of concurrent sessions should be defined based on
mission needs and the operational environment for each system.
  "
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000027-GPOS-00008"
  tag "gid": "V-72217"
  tag "rid": "SV-86841r1_rule"
  tag "stig_id": "RHEL-07-040000"
  tag "cci": "CCI-000054"
  tag "nist": ["AC-10", "Rev_4"]
  tag "check": "Verify the operating system limits the number of concurrent sessions
to \"10\" for all accounts and/or account types by issuing the following command:

# grep \"maxlogins\" /etc/security/limits.conf
* hard maxlogins 10

This can be set as a global domain (with the * wildcard) but may be set differently
for multiple domains.

If the \"maxlogins\" item is missing or the value is not set to \"10\" or less for
all domains that have the \"maxlogins\" item assigned, this is a finding."
  tag "fix": "Configure the operating system to limit the number of concurrent
sessions to \"10\" for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf:

* hard maxlogins 10"

  # @todo - update to handle other users and values 0-10
  describe limits_conf do
    its('*') { should include ["hard", "maxlogins", "10"] }
  end
end
