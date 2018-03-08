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

# Support for passed in Atrributes
files_to_skip = attribute(
                           'V_71849_Files_Allowed',
                           default: "grep -v 'cron' | grep -v '/var/cache/yum' | grep -v 'etc/sysconfig/iptables' | grep -v 'useradd' | grep -v 'ntp' | grep -v 'sysctl'",
                           description: 'Files that should be skipped'
                         )

control "V-71849" do
  title "The file permissions, ownership, and group membership of system files and
commands must match the vendor values."
  desc  "
    Discretionary access control is weakened if a user or group has access
permissions to system files and directories greater than the default.

    Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-0010.
  "
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000257-GPOS-00098"
  tag "gid": "V-71849"
  tag "rid": "SV-86473r2_rule"
  tag "stig_id": "RHEL-07-010010"
  tag "cci": "CCI-001494"
  tag "nist": ["AU-9", "Rev_4"]
  tag "cci": "CCI-001496"
  tag "nist": ["AU-9 (3)", "Rev_4"]
  tag "check": "Verify the file permissions, ownership, and group membership of
system files and commands match the vendor values.

Check the file permissions, ownership, and group membership of system files and
commands with the following command:

# rpm -Va | grep '^.M'

If there is any output from the command indicating that the ownership or group of a
system file or command, or a system file, has permissions less restrictive than the
default, this is a finding."

  tag "fix": "Run the following command to determine which package owns the file:

# rpm -qf <filename>

Reset the permissions of files within a package with the following command:

#rpm --setperms <packagename>

Reset the user and group ownership of files within a package with the following
command:

#rpm --setugids <packagename>"

  # @todo add puppet content to fix any rpms that get out of wack

# The following are known to be different and must be excluded. These are changed by the following 
# Chef Manage Cookbooks: 
# cron entries - stig/recipies/file_permissions.rb

#.M.......  /etc/cron.d 
#.M.......  /etc/cron.daily 
#.M.......  /etc/cron.hourly 
#.M.......  /etc/cron.monthly 
#.M.......  /etc/cron.weekly
#.M.......  c /etc/crontab

# /etc/default/useradd - stig/recipies/login_defs.rb
#.M5....T.  c /etc/default/useradd 

# /etc/ntp.conf - stig/recipies/ntp.rb
#.M.......  c /etc/ntp.conf

# /etc/sysctl.conf - stig
#SM5....T.  c /etc/sysctl.conf
#

#/etc/default/useradd - stig/recipies/ipv6.rb
#SM5....T.  c /etc/sysconfig/iptables

# /var/cache/yum -  if you ever clear out the yum cache to free system space
#.M.......    /var/cache/yum
							
  describe command("rpm -Va | grep '^.M' | #{files_to_skip} | wc -l") do
    its('stdout.strip') { should eq '0' }
  end

end 

