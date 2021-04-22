control 'V-233307' do
  title 'The Red Hat Enterprise Linux operating system SSH daemon must prevent remote hosts from connecting to the
    proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the
    sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to
    the loopback address and sets the hostname part of the DIPSLAY environment variable to localhost. This prevents
    remote hosts from connecting to the proxy display.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag 'gid': 'V-233307'
  tag 'rid': 'SV-233307r603301_rule'
  tag 'stig_id': 'RHEL-07-040711'
  tag 'fix_id': 'F-36466r603300_fix'
  tag 'cci': ['CCI-000366']
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': nil
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': nil
  tag 'check': 'Verify the SSH daemon prevents remote hosts from connecting to the proxy display.
    Check the SSH X11UseLocalhost setting with the following command:
    # sudo grep -i x11uselocalhost /etc/ssh/sshd_config
    X11UseLocalhost yes
    If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.'
  tag 'fix': 'Configure the SSH daemon to prevent remote hosts from connecting to the proxy display.
    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11UseLocalhost" keyword and set its
    value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is
    provided by a third-party vendor):
    X11UseLocalhost yes'
  
  describe sshd_config do
    its('X11UseLocalhost') { should eq 'yes' }
  end
end
