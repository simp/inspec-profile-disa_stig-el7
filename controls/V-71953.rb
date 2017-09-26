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

control "V-71953" do
  title "The operating system must not allow an unattended or automatic logon to the
system via a graphical user interface."
  desc  "Failure to restrict system access to authenticated users negatively impacts
operating system security."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71953"
  tag "rid": "SV-86577r1_rule"
  tag "stig_id": "RHEL-07-010440"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the operating system does not allow an unattended or
automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check for the value of the \"AutomaticLoginEnable\" in the \"/etc/gdm/custom.conf\"
file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a finding."
  tag "fix": "Configure the operating system to not allow an unattended or automatic
logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Add or edit the line for the \"AutomaticLoginEnable\" parameter in the [daemon]
section of the \"/etc/gdm/custom.conf\" file to \"false\":

[daemon]
AutomaticLoginEnable=false"

  custom_conf = file('/etc/gdm/custom.conf')

  only_if { custom_conf.exist? }

  describe "In #{custom_conf.path}:[daemon]" do
    context 'AutomaticLoginEnable' do
      it { expect(ini(custom_conf.path)['daemon'][subject]).to cmp 'false' }
    end
  end
end
