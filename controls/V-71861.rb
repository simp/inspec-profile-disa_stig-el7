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

BANNER_MESSAGE_TEXT_GUI = attribute('banner_message_text_gui',
default: "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

 -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

 -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
description: 'The banner message  must display the Standard Mandatory DoD Notice and Consent Banner before granting access.')

control "V-71861" do
  title "The operating system must display the approved Standard Mandatory DoD
Notice and Consent Banner before granting local or remote access to the system via a
graphical user logon."
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

\"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

    \"I've read & consent to terms in IS user agreem't.\"

    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-0008.
  "
  if package('gnome-desktop3').installed?
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000023-GPOS-00006"
  tag "gid": "V-71861"
  tag "rid": "SV-86485r2_rule"
  tag "stig_id": "RHEL-07-010040"
  tag "cci": "CCI-000048"
  tag "nist": ["AC-8 a", "Rev_4"]
  tag "check": "Verify the operating system displays the approved Standard Mandatory
DoD Notice and Consent Banner before granting access to the operating system via a
graphical user logon.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Check that the operating system displays the exact approved Standard Mandatory DoD
Notice and Consent Banner text with the command:

# grep banner-message-text /etc/dconf/db/local.d/*
banner-message-text=
‘You are accessing a U.S. Government (USG) Information System (IS) that is provided
for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the
following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes
including, but not limited to, penetration testing, COMSEC monitoring, network
operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to
routine monitoring, interception, and search, and may be disclosed or used for any
USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to
protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or
CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications
and work product are private and confidential. See User Agreement for details.’

If the banner does not match the approved Standard Mandatory DoD Notice and Consent
Banner, this is a finding."
  tag "fix": "Configure the operating system to display the approved Standard
Mandatory DoD Notice and Consent Banner before granting access to the system.

Note: If the system does not have GNOME installed, this requirement is Not
Applicable.

Create a database to contain the system-wide graphical user logon settings (if it
does not already exist) with the following command:

# touch /etc/dconf/db/local.d/01-banner-message

Add the following line to the [org/gnome/login-screen] section of the
\"/etc/dconf/db/local.d/01-banner-message\":

[org/gnome/login-screen]
banner-message-text=’You are accessing a U.S. Government (USG) Information System
(IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the
following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes
including, but not limited to, penetration testing, COMSEC monitoring, network
operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to
routine monitoring, interception, and search, and may be disclosed or used for any
USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to
protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or
CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications
and work product are private and confidential. See User Agreement for details.’"

  describe.one do
    describe command("grep banner-message-text /etc/dconf/db/local.d/*") do
      its('stdout') { should cmp BANNER_MESSAGE_TEXT_GRAPHICAL_GUI }
    end

    describe command("grep banner-message-text /etc/dconf/db/local.d/*") do
      its('stdout') { should cmp "banner-message-text='I\'ve read & consent to terms in IS user agreem\'t.'"}
    end
  end if package('gnome-desktop3').installed?

    describe "The system does not have GNOME installed" do
      skip "The system does not have GNOME installed, this requirement is Not
      Applicable."
    end if !package('gnome-desktop3').installed?
end
