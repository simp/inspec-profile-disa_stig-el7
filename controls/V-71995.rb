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

control "V-71995" do
  title "The operating system must define default permissions for all authenticated
users in such a way that the user can only read and modify their own files."
  desc  "Setting the most restrictive default permissions ensures that when new
accounts are created, they do not have unnecessary access."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000480-GPOS-00228"
  tag "gid": "V-71995"
  tag "rid": "SV-86619r1_rule"
  tag "stig_id": "RHEL-07-020240"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the operating system defines default permissions for all
authenticated users in such a way that the user can only read and modify their own
files.

Check for the value of the \"UMASK\" parameter in \"/etc/login.defs\" file with the
following command:

Note: If the value of the \"UMASK\" parameter is set to \"000\" in
\"/etc/login.defs\" file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs
UMASK  077

If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\" parameter
is missing or is commented out, this is a finding."
  tag "fix": "Configure the operating system to define default permissions for all
authenticated users in such a way that the user can only read and modify their own
files.

Add or edit the line for the \"UMASK\" parameter in \"/etc/login.defs\" file to
\"077\":

UMASK  077"

  describe login_defs do
    its('UMASK') { should eq '077' }
  end
end
