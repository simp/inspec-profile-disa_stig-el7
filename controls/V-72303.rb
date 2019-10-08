# encoding: utf-8
#
control "V-72303" do
  title "Remote X connections for interactive users must be encrypted."
  desc  "Open X displays allow an attacker to capture keystrokes and execute
commands remotely."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72303"
  tag "rid": "SV-86927r3_rule"
  tag "stig_id": "RHEL-07-040710"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  desc "check", "Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config

X11Forwarding yes

If the \"X11Forwarding\" keyword is set to \"no\", is missing, or is commented
out, this is a finding."
  desc "fix", "Configure SSH to encrypt connections for interactive users.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for the
\"X11Forwarding\" keyword and set its value to \"yes\" (this file may be named
differently or be in a different location if using a version of SSH that is
provided by a third-party vendor):

X11Forwarding yes

The SSH service must be restarted for changes to take effect."
  tag "fix_id": "F-78657r5_fix"

  describe sshd_config do
    its('X11Forwarding') { should cmp 'yes' }
  end
end
