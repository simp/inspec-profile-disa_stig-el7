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

control "V-72281" do
  title "For systems using DNS resolution, at least two name servers must be
configured."
  desc  "To provide availability for name resolution services, multiple redundant
name servers are mandated. A failure in name resolution could lead to the failure of
security functions requiring name resolution, which may include time
synchronization, centralized authentication, and remote system logging."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72281"
  tag "rid": "SV-86905r1_rule"
  tag "stig_id": "RHEL-07-040600"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Determine whether the system is using local or DNS name resolution
with the following command:

# grep hosts /etc/nsswitch.conf
hosts:   files dns

If the DNS entry is missing from the host’s line in the \"/etc/nsswitch.conf\" file,
the \"/etc/resolv.conf\" file must be empty.

Verify the \"/etc/resolv.conf\" file is empty with the following command:

# ls -al /etc/resolv.conf
-rw-r--r--  1 root root        0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the \"/etc/resolv.conf\" file is not
empty, this is a finding.

If the DNS entry is found on the host’s line of the \"/etc/nsswitch.conf\" file,
verify the operating system is configured to use two or more name servers for DNS
resolution.

Determine the name servers used by the system with the following command:

# grep nameserver /etc/resolv.conf
nameserver 192.168.1.2
nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a finding."
  tag "fix": "Configure the operating system to use two or more name servers for DNS
resolution.

Edit the \"/etc/resolv.conf\" file to uncomment or add the two or more
\"nameserver\" option lines with the IP address of local authoritative name servers.
If local host resolution is being performed, the \"/etc/resolv.conf\" file must be
empty. An empty \"/etc/resolv.conf\" file can be created as follows:

# echo -n > /etc/resolv.conf

And then make the file immutable with the following command:

# chattr +i /etc/resolv.conf

If the \"/etc/resolv.conf\" file must be mutable, the required configuration must be
documented with the Information System Security Officer (ISSO) and the file must be
verified by the system file integrity tool."

  # @todo - set up tests where determine if local/dns and then carry out test
  describe.one do
    # Case when local auth used
    describe file("/etc/resolve.conf") do
      it('size') { should match eq 0 }
    end
    # Case when DNS used
    describe command("grep nameserver /etc/resolv.conf") do
      its('stdout.strip') { should match /^nameserver .+\s*\nnameserver .+\s*\n?$/}
    end
  end
end
