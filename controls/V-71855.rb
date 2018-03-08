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

control "V-71855" do
  title "The cryptographic hash of system files and commands must match vendor
values."
  desc  "
    Without cryptographic integrity protections, system command and files can be
altered by unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography enabling
distribution of the public key to verify the hash information while maintaining the
confidentiality of the key used to generate the hash.
  "
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-71855"
  tag "rid": "SV-86479r2_rule"
  tag "stig_id": "RHEL-07-010020"
  tag "cci": "CCI-000663"
  tag "nist": ["SA-7", "Rev_3"]
  tag "subsystems": ['rpm', 'package']
  tag "check": "Verify the cryptographic hash of system files and commands match the
vendor values.

Check the cryptographic hash of system files and commands with the following command:

Note: System configuration files (indicated by a \"c\" in the second column) are
expected to change over time. Unusual modifications should be investigated through
the system audit log.

# rpm -Va | grep '^..5'

If there is any output from the command for system binaries, this is a finding."

  tag "fix": "Run the following command to determine which package owns the file:

# rpm -qf <filename>

The package can be reinstalled from a yum repository using the command:

# sudo yum reinstall <packagename>

Alternatively, the package can be reinstalled from trusted media using the command:

# sudo rpm -Uvh <packagename>"


# Command expacts that we will only have changed Config Files (i..e files with the denoted 'c')
# We have purposely excluded /etc/inittab as this isn't considered a config file by RPM
# but will be changed stig::inittab cookbook to make the system STIG compliant for single-user
# mode booting. Excluding this file in your check below prevents a false positive finding.

# Broken - caused a false positive for /etc/inittab
#  describe command("rpm -Va | grep '^..5' | awk -F' ' '{ print $2 }'") do
#    its('stdout.strip') { should_not include 'b' }

# Fixed to avoid false positive finding by excuding /etc/inittab from changed files list
  describe command("rpm -Va | grep '^..5' | grep -v '/etc/inittab' | awk -F' ' '{ print $2 }'") do
    its('stdout.strip') { should match /^((c)*(\\n)*)*$/ }
  end
end
