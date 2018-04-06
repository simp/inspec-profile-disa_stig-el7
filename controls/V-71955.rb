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

# TODO Use the attribute from V-71953 for the custom.conf file path

control "V-71955" do
  title "The operating system must not allow an unrestricted logon to the system."
  desc  "Failure to restrict system access to authenticated users negatively impacts
operating system security."

if package('gnome-desktop3').installed?
  impact 0.7
else
  impact 0.0
end

  tag "gtitle": "SRG-OS-000480-GPOS-00229"
  tag "gid": "V-71955"
  tag "rid": "SV-86579r2_rule"
  tag "stig_id": "RHEL-07-010450"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the operating system does not allow an unrestricted logon to
the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check for the value of the \"TimedLoginEnable\" parameter in
\"/etc/gdm/custom.conf\" file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of \"TimedLoginEnable\" is not set to \"false\", this is a finding."
  tag "fix": "Configure the operating system to not allow an unrestricted account to
log on to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Add or edit the line for the \"TimedLoginEnable\" parameter in the [daemon] section
of the \"/etc/gdm/custom.conf\" file to \"false\":

[daemon]
TimedLoginEnable=false"

  custom_conf = file('/etc/gdm/custom.conf')

  describe "In #{custom_conf.path}:[daemon]" do
    context 'TimedLoginEnable' do
      it { expect(ini(custom_conf.path)['daemon'][subject]).to cmp 'false' }
    end
  end if package('gnome-desktop3').installed?

  describe "The system does not have GNOME installed" do
    skip "The system does not have GNOME installed, this requirement is Not Applicable."
  end if !package('gnome-desktop3').installed?
end
