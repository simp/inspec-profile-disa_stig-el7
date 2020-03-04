# encoding: utf-8
#

known_system_accounts = input('known_system_accounts')

disallowed_accounts = input('disallowed_accounts')

user_accounts = input('user_accounts')

control "V-72001" do
  title "The system must not have unnecessary accounts."
  desc  "Accounts providing no operational purpose provide additional
opportunities for system compromise. Unnecessary accounts include user accounts
for individuals not requiring access to the system and application accounts for
applications not installed on the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72001"
  tag "rid": "SV-86625r1_rule"
  tag "stig_id": "RHEL-07-020270"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ['accounts']
  desc "check", "Verify all accounts on the system are assigned to an active
system, application, or user account.

Obtain the list of authorized system accounts from the Information System
Security Officer (ISSO).

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

Accounts such as \"games\" and \"gopher\" are not authorized accounts as they
do not support authorized system functions.

If the accounts on the system do not match the provided documentation, or
accounts that do not support an authorized system function are present, this is
a finding."
  desc "fix", "Configure the system so all accounts on the system are assigned
to an active system, application, or user account.

Remove accounts that do not support approved system activities or that allow
for a normal user to perform administrative-level actions.

Document all authorized accounts on the system."
  tag "fix_id": "F-78353r1_fix"

  allowed_accounts = (known_system_accounts + user_accounts).uniq

  describe passwd do
    its('users') { should be_in allowed_accounts }
  end

  describe passwd do
    its('users') { should_not be_in disallowed_accounts }
  end
end
