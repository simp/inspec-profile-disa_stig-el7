# encoding: utf-8
#
control "V-72095" do
  title "All privileged function executions must be audited."
  desc  "Misuse of privileged functions, either intentionally or
unintentionally by authorized users, or by unauthorized external entities that
have compromised information system accounts, is a serious and ongoing concern
and can have significant adverse impacts on organizations. Auditing the use of
privileged functions is one way to detect such misuse and identify the risk
from insider threats and the advanced persistent threat."
  impact 0.5
  tag "gtitle": "SRG-OS-000327-GPOS-00127"
  tag "gid": "V-72095"
  tag "rid": "SV-86719r5_rule"
  tag "stig_id": "RHEL-07-030360"
  tag "cci": ["CCI-002234"]
  tag "documentable": false
  tag "nist": ["AC-6 (9)", "Rev_4"]
  tag "subsystems": ['audit', 'auditd', 'audit_rule']
  tag "filesystem_heavy": true
  desc "check", "Verify the operating system audits the execution of privileged
functions.

To find relevant setuid and setgid programs, use the following command once for
each local partition [PART]:

# find [PART] -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null

Run the following command to verify entries in the audit rules for all programs
found with the previous command:

# grep -i \"<suid_prog_with_full_path>\" /etc/audit/audit.rules
-a always,exit -F path=\"<suid_prog_with_full_path>\" -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid

All \"setuid\" and \"setgid\" files on the system must have a corresponding
audit rule, or must have an audit rule for the (sub) directory that contains
the \"setuid\"/\"setgid\" file.

If all \"setuid\"/\"setgid\" files on the system do not have audit rule
coverage, this is a finding."
  desc "fix", "Configure the operating system to audit the execution of
privileged functions.

To find the relevant \"setuid\"/\"setgid\" programs, run the following command
for each local partition [PART]:

# find [PART] -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null

For each \"setuid\"/\"setgid\" program on the system, which is not covered by
an audit rule for a (sub) directory (such as \"/usr/sbin\"), add a line of the
following form to \"/etc/audit/rules.d/audit.rules\", where
<suid_prog_with_full_path> is the full path to each \"setuid\"/\"setgid\"
program in the list:

-a always,exit -F path=<suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid"
  tag "fix_id": "F-78447r7_fix"

  # Tried to make this as safe as possible
  target_files = command(%(find / -xautofs -noleaf -wholename '/proc' -prune -o -wholename '/sys' -prune -o -wholename '/dev' -prune -o -type f \\( -perm -4000 -o -perm -2000 \\) -print 2>/dev/null)).stdout.strip.lines

  target_files.each do |target_file|
    # target_file still contains \n, need to chomp it
    describe auditd.file(target_file.chomp) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end
    # Resource creates data structure including all usages of file
    @perms = auditd.file(target_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  end
end
