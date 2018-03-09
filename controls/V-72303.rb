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

control "V-72303" do
  title "Remote X connections for interactive users must be encrypted."
  desc  "Open X displays allow an attacker to capture keystrokes and execute
commands remotely."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72303"
  tag "rid": "SV-86927r2_rule"
  tag "stig_id": "RHEL-07-040710"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config
X11Fowarding yes

If the \"X11Forwarding\" keyword is set to \"no\", is missing, or is commented out,
this is a finding."
  tag "fix": "Configure SSH to encrypt connections for interactive users.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for the
\"X11Forwarding\" keyword and set its value to \"yes\" (this file may be named
differently or be in a different location if using a version of SSH that is provided
by a third-party vendor):

X11Fowarding yes

The SSH service must be restarted for changes to take effect."

# The sshd_config command uses lowercases. 
# So also test with a grep... grep will work 
# both will succeed on an accurate configuration
  describe.one do
     describe sshd_config do
       its('x11forwarding') { should cmp 'yes' }
     end
     describe command("grep -i 'X11Forwarding' /etc/ssh/sshd_config | awk '{print tolower($2)}'") do
       its('stdout.strip') { should eq 'yes' }
     end
  end
end

