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

file_integ_tool = attribute(
  'file_integ_tool',
  default: 'aide',
  description: "Tool used to determine file integrity"
)

control "V-71975" do
  title "Designated personnel must be notified if baseline configurations are
changed in an unauthorized manner."
  desc  "
    Unauthorized changes to the baseline configuration could make the system
vulnerable to various attacks or allow unauthorized access to the operating system.
Changes to operating system configurations can have unintended side effects, some of
which may be relevant to security.

    Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security state of
the operating system. The operating system's Information Management Officer
(IMO)/Information System Security Officer (ISSO) and System Administrators (SAs)
must be notified via email and/or monitoring system trap when there is an
unauthorized modification of a configuration item.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000363-GPOS-00150"
  tag "gid": "V-71975"
  tag "rid": "SV-86599r1_rule"
  tag "stig_id": "RHEL-07-020040"
  tag "cci": "CCI-001744"
  tag "nist": ["CM-3 (5)", "Rev_4"]
  tag "check": "Verify the operating system notifies designated personnel if
baseline configurations are changed in an unauthorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment
(AIDE) may be used, but the tool must be executed and notify specified individuals
via email or an alert.

Check to see if AIDE is installed on the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the SA how file integrity checks are performed on the
system.

Check for the presence of a cron job running routinely on the system that executes
AIDE to scan for changes to the system baseline. The commands used in the example
will use a daily occurrence.

Check the \"/etc/cron.daily\" subdirectory for a \"crontab\" file controlling the
execution of the file integrity application. For example, if AIDE is installed on
the system, use the following commands:

# ls -al /etc/cron.daily | grep aide
-rwxr-xr-x  1 root root        32 Jul  1  2011 aide

AIDE does not have a configuration that will send a notification, so the cron job
uses the mail application on the system to email the results of the file integrity
run as in the following example:

# more /etc/cron.daily/aide
0 0 * * * /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity
check run\" root@sysname.mil

If the file integrity application does not notify designated personnel of changes,
this is a finding."
  tag "fix": "Configure the operating system to notify designated personnel if
baseline configurations are changed in an unauthorized manner. The AIDE tool can be
configured to email designated personnel through the use of the cron system.

The following example output is generic. It will set cron to run AIDE daily and to
send email at the completion of the analysis.

# more /etc/cron.daily/aide
0 0 * * * /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity
check run\" root@sysname.mil"

  describe package(file_integ_tool) do
    it { should be_installed }
  end
  describe.one do
    describe file("cat /etc/cron.daily/#{file_integ_tool}") do
      its('content') { should match /\/bin\/mail/ }
    end
    describe file("/etc/cron.weekly/#{file_integ_tool}") do
      its('content') { should match /\/bin\/mail/ }
    end
  end
end
