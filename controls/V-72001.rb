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

# Will need to have attribute updated in YML to reflect list of authorized system accounts
system_accounts = attribute(
  'V_72001_System_Accounts',
  default: [
        'root',
        'bin',
        'daemon',
        'adm',
        'lp',
        'sync',
        'shutdown',
        'halt',
        'mail',
        'operator',
#       'games', # Should Be Removed
#       'ftp', # Should Be Removed
        'nobody',
        'systemd-bus-proxy',
        'systemd-network',
        'dbus',
        'polkitd',
        'tss', #  Account used by the trousers package to sandbox the tcsd daemon
        'postfix', # Service Account for Postfix Mail Daemon
        'chrony', # Service Account for the Chrony Time Service
        'sshd', # Service Account for SSH
        'ec2-user', # Service Account for EC2 Access in AWS
        'sssd', # Service Account for the SSSH Authentication service
        'rpc', # Service Account RPCBind Daemon
        'unbound', # Service Account UnBound Daemon
        'ntp' # Service Account for NTPD Daemon
  ],
  description: "System accounts that support approved system activities."
)

control "V-72001" do
  title "The system must not have unnecessary accounts."
  desc  "Accounts providing no operational purpose provide additional opportunities
for system compromise. Unnecessary accounts include user accounts for individuals
not requiring access to the system and application accounts for applications not
installed on the system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72001"
  tag "rid": "SV-86625r1_rule"
  tag "stig_id": "RHEL-07-020270"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all accounts on the system are assigned to an active system,
application, or user account.

Obtain the list of authorized system accounts from the Information System Security
Officer (ISSO).

Check the system accounts on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin

Accounts such as \"games\" and \"gopher\" are not authorized accounts as they do not
support authorized system functions.

If the accounts on the system do not match the provided documentation, or accounts
that do not support an authorized system function are present, this is a finding."
  tag "fix": "Configure the system so all accounts on the system are assigned to an
active system, application, or user account.

Remove accounts that do not support approved system activities or that allow for a
normal user to perform administrative-level actions.

Document all authorized accounts on the system."

  describe passwd do
    its('users') { should be_in system_accounts }
  end
end
