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

control "V-71859" do
  title "The operating system must display the Standard Mandatory DoD Notice and
Consent Banner before granting local or remote access to the system via a graphical
user logon."
  desc  "
    Display of a standardized and approved use notification before granting access
to the operating system ensures privacy and security notification verbiage used is
consistent with applicable federal laws, Executive Orders, directives, policies,
regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces with
human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use the
following verbiage for operating systems that can accommodate banners of 1300
characters:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to
the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used for
any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications
and work product are private and confidential. See User Agreement for details.\"

    Use the following verbiage for operating systems that have severe limitations on
the number of characters that can be displayed in the banner:

    \"I've read & consent to terms in IS user agreem't.\"

    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007,
    SRG-OS-000228-GPOS-0008.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000023-GPOS-00006"
  tag "gid": "V-71859"
  tag "rid": "SV-86483r2_rule"
  tag "stig_id": "RHEL-07-010030"
  tag "cci": "CCI-000048"
  tag "nist": ["AC-8 a", "Rev_4"]
  tag "check": "Verify the operating system displays the Standard Mandatory DoD
  Notice and Consent Banner before granting access to the operating system via a
  graphical user logon.

  Note: If the system does not have GNOME installed, this requirement is Not
  Applicable.

  Check to see if the operating system displays a banner at the logon screen with the
  following command:

  # grep banner-message-enable /etc/dconf/db/local.d/* banner-message-enable=true

  If \"banner-message-enable\" is set to \"false\" or is missing, this is a finding."

  tag "fix": "Configure the operating system to display the Standard Mandatory DoD
  Notice and Consent Banner before granting access to the system.

  Note: If the system does not have GNOME installed, this requirement is Not
  Applicable.

  Create a database to contain the system-wide graphical user logon settings (if it
  does not already exist) with the following command:

  # touch /etc/dconf/db/local.d/01-banner-message

  Add the following line to the [org/gnome/login-screen] section of the
  \"/etc/dconf/db/local.d/01-banner-message\":

  [org/gnome/login-screen]
  banner-message-enable=true"

  only_if { command('dconf').exist? or file('/etc/gdm/custom.conf').exist? }

  describe command("dconf read /org/gnome/login-screen/banner-mesage-enable") do
    its('stdout'.strip) { should eq 'true'}
  end
end
