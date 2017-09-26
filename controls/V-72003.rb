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

control "V-72003" do
  title "All Group Identifiers (GIDs) referenced in the /etc/passwd file must be
defined in the /etc/group file."
  desc  "If a user is assigned the GID of a group not existing on the system, and a
group with the GID is subsequently created, the user may have unintended rights to
any files associated with the group."
  impact 0.3
  tag "severity": "low"
  tag "gtitle": "SRG-OS-000104-GPOS-00051"
  tag "gid": "V-72003"
  tag "rid": "SV-86627r1_rule"
  tag "stig_id": "RHEL-07-020300"
  tag "cci": "CCI-000764"
  tag "nist": ["IA-2", "Rev_4"]
  tag "check": "Verify all GIDs referenced in the \"/etc/passwd\" file are defined
in the \"/etc/group\" file.

Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in \"/etc/passwd\" file are returned as not defined in
\"/etc/group\" file, this is a finding."
  tag "fix": "Configure the system to define all GIDs found in the \"/etc/passwd\"
file by modifying the \"/etc/group\" file to add any non-existent group referenced
in the \"/etc/passwd\" file, or change the GIDs referenced in the \"/etc/passwd\"
file to a group that exists in \"/etc/group\"."

  passwd.gids.each do |gid|
    describe etc_group do
      its('gids') { should include gid.to_i }
    end
  end
end
