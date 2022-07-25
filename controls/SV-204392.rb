control 'SV-204392' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership,
    and group membership of system files and commands match the vendor values.'
  desc 'Discretionary access control is weakened if a user or group has access permissions to system files and
    directories greater than the default.'
  desc 'rationale', ''
  desc 'check', %q{Verify the file permissions, ownership, and group membership of system files and commands match the
    vendor values.
    Check the default file permissions, ownership, and group membership of system files and commands with the following
    command:
    # for i in `rpm -Va | egrep '^.{1}M|^.{5}U|^.{6}G' | cut -d " " -f 4,5`;do for j in `rpm -qf $i`;do rpm -ql $j
    --dump | cut -d " " -f 1,5,6,7 | grep $i;done;done
    /var/log/gdm 040755 root root
    /etc/audisp/audisp-remote.conf 0100640 root root
    /usr/bin/passwd 0104755 root root
    For each file returned, verify the current permissions, ownership, and group membership:
    # ls -la <filename>
    -rw-------. 1 root root 133 Jan 11 13:25 /etc/audisp/audisp-remote.conf
    If the file is more permissive than the default permissions, this is a finding.
    If the file is not owned by the default owner and is not documented with the Information System Security Officer
    (ISSO), this is a finding.
    If the file is not a member of the default group and is not documented with the Information System Security Officer
    (ISSO), this is a finding.}
  desc  'fix', "
    Run the following command to determine which package owns the file:

    # rpm -qf <filename>

    Reset the user and group ownership of files within a package with the
following command:

    #rpm --setugids <packagename>


    Reset the permissions of files within a package with the following command:

    #rpm --setperms <packagename>
  "
  impact 0.7
  tag 'legacy': ['V-71849', 'SV-86473']
  tag 'severity': 'high'
  tag 'gtitle': 'SRG-OS-000257-GPOS-00098'
  tag 'satisfies': ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000278-GPOS-00108']
  tag 'gid': 'V-204392'
  tag 'rid': 'SV-204392r646841_rule'
  tag 'stig_id': 'RHEL-07-010010'
  tag 'fix_id': 'F-36302r646840_fix'
  tag 'cci': ['CCI-001494', 'CCI-001496', 'CCI-002165', 'CCI-002235']
  tag nist: ['AU-9', 'AU-9 (3)', 'AC-3 (4)', 'AC-6 (10)']
  tag subsystems: ["permissions","package","rpm"]
  tag 'host', 'container'

  if input('disable_slow_controls')
    describe "This control consistently takes a long time to run and has been disabled
    using the disable_slow_controls attribute." do
      skip "This control consistently takes a long time to run and has been disabled
            using the disable_slow_controls attribute. You must enable this control for a
            full accredidation for production."
    end
  else

    allowlist = input('rpm_verify_perms_except')

    misconfigured_packages = command('rpm -Va').stdout.split("\n")
      .select{ |package| package[0..7].match(/M|U|G/) }
      .map{ |package| package.match(/\S+$/)[0] }

    unless misconfigured_packages.empty?
      describe "The list of rpm packages with permissions changed from the vendor values" do
        fail_msg = "Files that have been modified from vendor-approved permissions but are not in the allowlist: #{(misconfigured_packages - allowlist).join(', ')}"
        it "should all appear in the allowlist" do
          expect(misconfigured_packages).to all( be_in allowlist ), fail_msg
        end
      end
    else
      describe "The list of rpm packages with permissions changed from the vendor values" do
        subject { misconfigured_packages }
        it { should be_empty }
      end
    end
  end
end
