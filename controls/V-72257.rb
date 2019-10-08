# encoding: utf-8
#
control "V-72257" do
  title "The SSH private host key files must have mode 0600 or less permissive."
  desc  "If an unauthorized user obtains the private SSH host key file, the
host could be impersonated."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72257"
  tag "rid": "SV-86881r1_rule"
  tag "stig_id": "RHEL-07-040420"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "subsystems": ["ssh"]
  desc "check", "Verify the SSH private host key files have mode \"0600\" or
less permissive.

The following command will find all SSH private key files on the system:

# find / -name '*ssh_host*key'

Check the mode of the private host key files under \"/etc/ssh\" file with the
following command:

# ls -lL /etc/ssh/*key
-rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key
-rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key
-rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key

If any file has a mode more permissive than \"0600\", this is a finding."
  desc "fix", "Configure the mode of SSH private host key files under
\"/etc/ssh\" to \"0600\" with the following command:

# chmod 0600 /etc/ssh/ssh_host*key"
  tag "fix_id": "F-78611r3_fix"

  key_files = command("find /etc/ssh -xdev -name '*ssh_host*key' -perm /177").stdout.split("\n")
  if !key_files.nil? and !key_files.empty?
    key_files.each do |keyfile|
      describe file(keyfile) do
        it { should_not be_executable.by('owner') }
        it { should_not be_readable.by('group') }
        it { should_not be_writable.by('group') }
        it { should_not be_executable.by('group') }
        it { should_not be_readable.by('others') }
        it { should_not be_writable.by('others') }
        it { should_not be_executable.by('others') }
      end
    end
  else
    describe "No files have a more permissive mode." do
      subject { key_files.nil? or key_files.empty? }
      it { should eq true }
    end
  end
end
