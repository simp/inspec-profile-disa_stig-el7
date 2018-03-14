BANNER_MESSAGE_TEXT_RAL = attribute('banner_message_text_ral',
default: "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.                                                                                

By using this IS (which includes any device attached to this IS), you consent to the following conditions: 

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 

-At any time, the USG may inspect and seize data stored on this IS.                    

-Communications using, or data stored on, this IS are not private, are subject  to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.            

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.                  

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
description: 'The banner message  must display the Standard Mandatory DoD Notice and Consent Banner before granting access.')

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

control "V-72225" do
  title "The Standard Mandatory DoD Notice and Consent Banner must be displayed
immediately prior to, or as part of, remote access logon prompts."
  desc  "
    Display of a standardized and approved use notification before granting access
to the publicly accessible operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws, Executive
Orders, directives, policies, regulations, standards, and guidance.

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

    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007 ,
SRG-OS-000228-GPOS-0008.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000023-GPOS-00006"
  tag "gid": "V-72225"
  tag "rid": "SV-86849r2_rule"
  tag "stig_id": "RHEL-07-040170"
  tag "cci": "CCI-000048"
  tag "nist": ["AC-8 a", "Rev_4"]
  tag "cci": "CCI-000050"
  tag "nist": ["AC-8 b", "Rev_4"]
  tag "cci": "CCI-001384"
  tag "nist": ["AC-8 c 1", "Rev_4"]
  tag "cci": "CCI-001385"
  tag "nist": ["AC-8 c 2", "Rev_4"]
  tag "cci": "CCI-001386"
  tag "nist": ["AC-8 c 2", "Rev_4"]
  tag "cci": "CCI-001387"
  tag "nist": ["AC-8 c 2", "Rev_4"]
  tag "cci": "CCI-001388"
  tag "nist": ["AC-8 c 3", "Rev_4"]
  tag "check": "Verify any publicly accessible connection to the operating system
displays the Standard Mandatory DoD Notice and Consent Banner before granting access
to the system.

Check for the location of the banner file being used with the following command:

# grep -i banner /etc/ssh/sshd_config

banner=/etc/issue

This command will return the banner keyword and the name of the file that contains
the ssh banner (in this case \"/etc/issue\").

If the line is commented out, this is a finding.

View the file specified by the banner keyword to check that it matches the text of
the Standard Mandatory DoD Notice and Consent Banner:

\"You are accessing a U.S. Government (USG) Information System (IS) that is provided
for USG-authorized use only. By using this IS (which includes any device attached to
this IS), you consent to the following conditions:

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

If the system does not display a graphical logon banner or the banner does not match
the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the file does not match the Standard Mandatory DoD Notice and Consent
Banner, this is a finding."
  tag "fix": "Configure the operating system to display the Standard Mandatory DoD
Notice and Consent Banner before granting access to the system via the ssh.

Edit the \"/etc/ssh/sshd_config\" file to uncomment the banner keyword and configure
it to point to a file that will contain the logon banner (this file may be named
differently or be in a different location if using a version of SSH that is provided
by a third-party vendor). An example configuration line is:

banner=/etc/issue

Either create the file containing the banner or replace the text in the file with
the Standard Mandatory DoD Notice and Consent Banner. The DoD required text is:

\"You are accessing a U.S. Government (USG) Information System (IS) that is provided
for USG-authorized use only. By using this IS (which includes any device attached to
this IS), you consent to the following conditions:

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
and work product are private and confidential. See User Agreement for details.\"

The SSH service must be restarted for changes to take effect."

  # @todo - dynamically find where banner stored
  describe file("/etc/issue") do
    its('content') { should cmp BANNER_MESSAGE_TEXT_RAL }
  end
end
