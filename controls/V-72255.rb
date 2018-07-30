# encoding: utf-8
#
control "V-72255" do
  title "The SSH public host key files must have mode 0644 or less permissive."
  desc  "If a public host key file is modified by an unauthorized user, the SSH
service may be compromised."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72255"
  tag "rid": "SV-86879r1_rule"
  tag "stig_id": "RHEL-07-040410"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  tag "check": "Verify the SSH public host key files have mode \"0644\" or less
permissive.

Note: SSH public key files may be found in other directories on the system
depending on the installation.

The following command will find all SSH public key files on the system:

# find /etc/ssh -name '*.pub' -exec ls -lL {} \\;

-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than \"0644\", this is a finding."
  tag "fix": "Note: SSH public key files may be found in other directories on
the system depending on the installation.

Change the mode of public host key files under \"/etc/ssh\" to \"0644\" with
the following command:

# chmod 0644 /etc/ssh/*.key.pub"
  tag "fix_id": "F-78609r1_fix"

  pub_files = command("find /etc/ssh -xdev -name '*.pub' -perm /133").stdout.split("\n")
  if !pub_files.nil? and !pub_files.empty?
    pub_files.each do |pubfile|
      describe file(pubfile) do
        it { should_not be_executable.by('user') }
        it { should_not be_executable.by('group') }
        it { should_not be_writable.by('group') }
        it { should_not be_executable.by('others') }
        it { should_not be_writable.by('others') }
      end
    end
  else
     describe "No files have a more permissive mode." do
      subject { pub_files.nil? or pub_files.empty? }
      it { should eq true }
    end
  end
end
