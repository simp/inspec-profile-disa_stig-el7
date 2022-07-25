control 'SV-250312' do
  title 'The Red Hat Enterprise Linux operating system must confine SELinux users to roles that conform to least privilege.'
  desc  "Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.\n\nPrivileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag satisfies: nil
  tag gid: 'V-250312'
  tag rid: 'SV-250312r792843_rule'
  tag stig_id: 'RHEL-07-020021'
  tag fix_id: 'F-53700r792842_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag legacy: []
  tag subsystems: ["selinux"]
  tag 'host'
  tag check: "Note: Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux.\n\nVerify the operating system confines SELinux users to roles that conform to least privilege.\n\nCheck the SELinux User list to SELinux Roles mapping by using the following command:\n\n$ sudo semanage user -l\nSELinuxUser LabelingPrefix MLS/MCSLevel MLS/MCSRange SELinuxRoles\nguest_u            user  s0  s0  guest_r\nroot                   user  s0  s0-s0:c0.c1023  staff_r sysadm_r system_r unconfined_r\nstaff_u              user  s0  s0-s0:c0.c1023  staff_r sysadm_r\nsysadm_u         user  s0  s0-s0:c0.c1023  sysadm_r \nsystem_u          user  s0  s0-s0:c0.c1023  system_r unconfined_r\nunconfined_u  user  s0  s0-s0:c0.c1023  system_r unconfined_r\nuser_u               user  s0  s0  user_r\nxguest_u           user  s0  s0  xguest_r\n\nIf the output differs from the above example, ask the SA to demonstrate how the SELinux User mappings are exercising least privilege. If deviations from the example are not documented with the ISSO and do not demonstrate least privilege, this is a finding."
  tag fix: "Configure the operating system to confine SELinux users to roles that conform to least privilege.\n\nUse the following command to map the \"staff_u\" SELinux user to the \"staff_r\" and \"sysadm_r\" roles:\n\n$ sudo semanage user -m staff_u -R staff_r -R sysadm_r\n\nUse the following command to map the \"user_u\" SELinux user to the \"user_r\" role:\n\n$ sudo semanage -m user_u -R user_r"

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container -- kernel config" do
      skip "Control not applicable within a container -- kernel config"
    end
  else

    expected_mapping = {
      'staff_u' => ['staff_r', 'sysadm_r'],
      'user_u' => ['user_r']
    }

    selinux_users = command('semanage user -l').stdout.strip

    describe "SELinux user-role mappings" do
      expected_mapping.keys.each do |user|

        staff_user_mapping = selinux_users.match(/^#{user}.+\d+\s+(?<roles>.*)$/)
        staff_user_roles = staff_user_mapping['roles'].split.to_set unless staff_user_mapping.nil?

        it "should set SELinux user \'#{user}\' to only have roles: #{expected_mapping[user].join(' ')}" do
          expect(staff_user_mapping).not_to be_nil, "No user \'#{user}\'found"
          expect(staff_user_roles).to eq expected_mapping[user].to_set
        end
      end
    end
  end
end
