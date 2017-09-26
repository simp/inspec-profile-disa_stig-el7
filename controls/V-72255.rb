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

control "V-72255" do
  title "The SSH public host key files must have mode 0644 or less permissive."
  desc  "If a public host key file is modified by an unauthorized user, the SSH
service may be compromised."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72255"
  tag "rid": "SV-86879r1_rule"
  tag "stig_id": "RHEL-07-040410"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the SSH public host key files have mode \"0644\" or less
permissive.

Note: SSH public key files may be found in other directories on the system depending
on the installation.

The following command will find all SSH public key files on the system:

# find /etc/ssh -name '*.pub' -exec ls -lL {} \\;

-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than \"0644\", this is a finding."
  tag "fix": "Note: SSH public key files may be found in other directories on the
system depending on the installation.

Change the mode of public host key files under \"/etc/ssh\" to \"0644\" with the
following command:

# chmod 0644 /etc/ssh/*.key.pub"

  pub_files = command("find /etc/ssh -xdev -name '*.pub' -perm /133").stdout.split("\n")
  pub_files.each do |pubfile|
    describe file(pubfile) do
      it { should_not be_executable.by('user') }
      it { should_not be_executable.by('group') }
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('others') }
      it { should_not be_writable.by('others') }
    end
  end
end
