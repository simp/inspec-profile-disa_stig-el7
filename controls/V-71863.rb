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

#TODO: Make sure this is acctually an onlyif on the GUI - ssh banner, ftp banner also use /etc/issue

#BANNER_MESSAGE_TEXT_CLI = attribute('banner_message_text_cli',
#  default: "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
#  By using this IS (which includes any device attached to this IS), you consent to the following conditions:
#    - The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
#    - At any time, the USG may inspect and seize data stored on this IS.
#    - Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
#    - This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
 #   - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
#  description: 'The banner message  must display the Standard Mandatory DoD Notice and Consent Banner before granting access.')

BANNER_MESSAGE_TEXT_CLI = attribute('banner_message_text_cli',
  default:"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
description: 'The banner message  must display the Standard Mandatory DoD Notice and Consent Banner before granting access.')

BANNER_MESSAGE_TEXT_CLI_LIMITED = attribute('banner_message_text_cli_limited',
default: "I've read & consent to terms in IS user agreem't.",
description: 'The banner message must display the Standard Mandatory DoD Notice and Consent Bann\
er before granting access.')


control "V-71863" do
  title "The operating system must display the Standard Mandatory DoD Notice and
Consent Banner before granting local or remote access to the system via a command
line user logon."
desc  "Display of a standardized and approved use notification before granting access
to the operating system ensures privacy and security notification verbiage used is
consistent with applicable federal laws, Executive Orders, directives, policies,
regulations, standards, and guidance. System use notifications are required only for
access via logon interfaces with human users and are not required when such human
interfaces do not exist. The banner must be formatted in accordance with applicable DoD policy.

Use the following verbiage for operating systems that can accommodate banners of 1300
characters:

`You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to
the following conditions:

  - The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.

  - At any time, the USG may inspect and seize data stored on this IS.

  - Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used for
any USG-authorized purpose.

  - This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.

  - Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications
and work product are private and confidential. See User Agreement for details.`

Use the following verbiage for operating systems that have severe limitations on
the number of characters that can be displayed in the banner:

  - `I've read & consent to terms in IS user agreem't.'`"

  impact 0.5

  tag "gtitle": "SRG-OS-000023-GPOS-00006"
  tag "gid": "V-71863"
  tag "rid": "SV-86487r1_rule"
  tag "stig_id": "RHEL-07-010050"
  tag "cci": "CCI-000048"
  tag "nist": ["AC-8 a", "Rev_4"]
  tag "check": "Verify the operating system displays the Standard Mandatory DoD
Notice and Consent Banner before granting access to the operating system via a
command line user logon.

Check to see if the operating system displays a banner at the command line logon
screen with the following command:

# more /etc/issue

The command should return the following text:
\"You are accessing a U.S. Government (USG) Information System (IS) that is provided
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
and work product are private and confidential. See User Agreement for details.\"

If the operating system does not display a graphical logon banner or the banner does
not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the \"/etc/issue\" file does not match the Standard Mandatory DoD
Notice and Consent Banner, this is a finding."
  tag "fix": "Configure the operating system to display the Standard Mandatory DoD
Notice and Consent Banner before granting access to the system via the command line
by editing the \"/etc/issue\" file.

Replace the default text with the Standard Mandatory DoD Notice and Consent Banner.
The DoD required text is:

\"You are accessing a U.S. Government (USG) Information System (IS) that is provided
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
protect USG interests -- not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or
CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications
and work product are private and confidential. See User Agreement for details.\""

  CLEAN_BANNER = BANNER_MESSAGE_TEXT_CLI.gsub(%r{[\r\n\s]}, '')
  CLEAN_BANNER_LIMITED = BANNER_MESSAGE_TEXT_CLI_LIMITED.gsub(%r{[\r\n\s]}, '')
  banner_file = file("/etc/issue")
  BANNER_MISSING = !banner_file.exist?

  describe "The banner text is not set because /etc/issue does not exist" do
    subject { BANNER_MISSING }
    it { should be false }
  end if BANNER_MISSING

  banner_message = banner_file.content.gsub(%r{[\r\n\s]}, '')
  describe.one do
    describe "The banner text should match the standard banner" do
      subject { banner_message }
      it { should cmp CLEAN_BANNER }
    end
    describe "The banner text should match the limited banner" do
      subject { banner_message }
      it{should cmp CLEAN_BANNER_LIMITED }
    end
  end if !BANNER_MISSING
end
