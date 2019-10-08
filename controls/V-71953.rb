# encoding: utf-8
#

# TODO make me an attribute - the custom.conf file path should be an attribute.

control "V-71953" do
  title "The operating system must not allow an unattended or automatic logon
to the system via a graphical user interface."
  desc  "Failure to restrict system access to authenticated users negatively
impacts operating system security."
if package('gdm').installed?
  impact 0.7
else
  impact 0.0
end
  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71953"
  tag "rid": "SV-86577r1_rule"
  tag "stig_id": "RHEL-07-010440"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["gdm"]
  desc "check", "Verify the operating system does not allow an unattended or
automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check for the value of the \"AutomaticLoginEnable\" in the
\"/etc/gdm/custom.conf\" file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a
finding."
  desc "fix", "Configure the operating system to not allow an unattended or
automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Add or edit the line for the \"AutomaticLoginEnable\" parameter in the [daemon]
section of the \"/etc/gdm/custom.conf\" file to \"false\":

[daemon]
AutomaticLoginEnable=false"
  tag "fix_id": "F-78305r1_fix"
  custom_conf = file('/etc/gdm/custom.conf')

  describe "In #{custom_conf.path}:[daemon]" do
    context 'AutomaticLoginEnable' do
      it { expect(ini(custom_conf.path)['daemon'][subject]).to cmp 'false' }
    end
  end if package('gdm').installed?

  describe "The system does not have GDM installed" do
    skip "The system does not have GDM installed, this requirement is Not Applicable."
  end if !package('gdm').installed?
end
