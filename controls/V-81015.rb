# encoding: utf-8
#
control "V-81015" do
  title "The Red Hat Enterprise Linux operating system must be configured to use the au-remote plugin."
  desc  "
  Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is 
  a common process in information systems with limited audit storage capacity. Without the configuration of 
  the \"au-remote\" plugin, the audisp-remote daemon will not off-load the logs from the system being audited.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "satisfies": ["SRG-OS-000342-GPOS-00133", "SRG-OS-000479-GPOS-00224"]
  tag "gid": "V-81015"
  tag "rid": "SV-95727r1_rule"
  tag "stig_id": "RHEL-07-030200"
  tag "cci": ["CCI-001851"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "subsystems": ["audit"]
  tag "check_id": "C-80729r1_chk"
  tag "fix_id": "F-87849r2_fix"
  desc "check", "
  Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

  Off-loading is a common process in information systems with limited audit storage capacity.

  Without the configuration of the \"au-remote\" plugin, the audisp-remote daemon will not off-load the logs from the system being audited.
  "
  desc "fix", "
  Edit the /etc/audisp/plugins.d/au-remote.conf file and change the value of \"active\" to \"yes\".

  The audit daemon must be restarted for changes to take effect:

  # service auditd restart
  "

  if file('/etc/audisp/plugins.d/au-remote.conf').exist?
    describe parse_config_file('/etc/audisp/plugins.d/au-remote.conf') do
      its('active') { should match %r{yes$} }
    end
  else
    describe "File '/etc/audisp/plugins.d/au-remote.conf' cannot be found. This test cannot be checked in a automated fashion and you must check it manually" do
      skip "File '/etc/audisp/plugins.d/au-remote.conf' cannot be found. This check must be performed manually"
    end
  end

end
