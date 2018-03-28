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

control "V-71987" do
  title "The operating system must remove all software components after updated
versions have been installed."
  desc  "Previous versions of software components that are not removed from the
information system after updates have been installed may be exploited by
adversaries. Some information technology products may remove older versions of
software automatically from the information system."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000437-GPOS-00194"
  tag "gid": "V-71987"
  tag "rid": "SV-86611r1_rule"
  tag "stig_id": "RHEL-07-020200"
  tag "cci": "CCI-002617"
  tag "nist": ["SI-2 (6)", "Rev_4"]
  tag "check": "Verify the operating system removes all software components after
updated versions have been installed.

Check if yum is configured to remove unneeded packages with the following command:

# grep -i clean_requirements_on_remove /etc/yum.conf
clean_requirements_on_remove=1

If \"clean_requirements_on_remove\" is not set to \"1\", \"True\", or \"yes\", or is
not set in \"/etc/yum.conf\", this is a finding."
  tag "fix": "Configure the operating system to remove all software components after
updated versions have been installed.

Set the \"clean_requirements_on_remove\" option to \"1\" in the \"/etc/yum.conf\"
file:

clean_requirements_on_remove=1"

  describe.one do
    describe parse_config_file("/etc/yum.conf") do
      its('clean_requirements_on_remove') { should match /^(1|True|yes)$/ }
    end
    describe command("grep -i 'clean_requirements_on_remove=' /etc/yum.conf | awk -F= '{print $2}'") do
      its('stdout.strip') { should eq '1' }
    end
  end
  
end
