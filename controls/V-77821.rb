# encoding: utf-8
#
control "V-77821" do
  title "The Datagram Congestion Control Protocol (DCCP) kernel module must be
disabled unless required."
  desc  "Disabling DCCP protects the system against exploitation of any flaws
in the protocol implementation."
  impact 0.5
  tag "gtitle": "SRG-OS-000378-GPOS-00163"
  tag "gid": "V-77821"
  tag "rid": "SV-92517r1_rule"
  tag "stig_id": "RHEL-07-020101"
  tag "cci": ["CCI-001958"]
  tag "documentable": false
  tag "nist": ["IA-3", "Rev_4"]
  tag "subsystems": ['dccp', 'kernel_module']
  desc "check", "Verify the operating system disables the ability to load the
DCCP kernel module.

Check to see if the DCCP kernel module is disabled with the following command:

# grep -r dccp /etc/modprobe.d/* | grep -i \"/bin/true\" | grep -v \"^#\"

install dccp /bin/true

If the command does not return any output, or the line is commented out, and
use of DCCP is not documented with the Information System Security Officer
(ISSO) as an operational requirement, this is a finding."
  desc "fix", "Configure the operating system to disable the ability to use the
DCCP kernel module.

Create a file under \"/etc/modprobe.d\" with the following command:

# touch /etc/modprobe.d/nodccp.conf

Add the following line to the created file:

install dccp /bin/true"
  tag "fix_id": "F-84521r2_fix"

  describe kernel_module('dccp') do
    it { should_not be_loaded }
    it { should be_blacklisted }
  end
end
