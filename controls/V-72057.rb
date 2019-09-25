# encoding: utf-8
#
control "V-72057" do
  title "Kernel core dumps must be disabled unless needed."
  desc  "Kernel core dumps may contain the full contents of system memory at
the time of the crash. Kernel core dumps may consume a considerable amount of
disk space and may result in denial of service by exhausting the available
space on the target file system partition."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72057"
  tag "rid": "SV-86681r1_rule"
  tag "stig_id": "RHEL-07-021300"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify that kernel core dumps are disabled unless needed.

Check the status of the \"kdump\" service with the following command:

# systemctl status kdump.service
kdump.service - Crash recovery kernel arming
   Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)
   Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago
 Main PID: 1130 (code=exited, status=0/SUCCESS)
kernel arming.

If the \"kdump\" service is active, ask the System Administrator if the use of
the service is required and documented with the Information System Security
Officer (ISSO).

If the service is active and is not documented, this is a finding."
  tag "fix": "If kernel core dumps are not required, disable the \"kdump\"
service with the following command:

# systemctl disable kdump.service

If kernel core dumps are required, document the need with the ISSO."
  tag "fix_id": "F-78409r1_fix"

  describe systemd_service('kdump.service') do
    it { should_not be_running }
  end
end
