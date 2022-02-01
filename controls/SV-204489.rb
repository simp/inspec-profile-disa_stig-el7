control 'SV-204489' do
  title 'The Red Hat Enterprise Linux operating system must have cron logging implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used
    to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  tag 'legacy': ['V-72051', 'SV-86675']
  desc 'rationale', ''
  desc 'check', 'Verify that "rsyslog" is configured to log cron events.
    Check the configuration of "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files for the cron facility with the
    following command:
    Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or
    "/etc/rsyslog.d/*.conf" files.
    # grep cron /etc/rsyslog.conf  /etc/rsyslog.d/*.conf
    cron.* /var/log/cron
    If the command does not return a response, check for cron logging all facilities by inspecting the
    "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.
    Look for the following entry:
    *.* /var/log/messages
    If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.'
  desc 'fix', 'Configure "rsyslog" to log all cron messages by adding or updating the following line to
    "/etc/rsyslog.conf" or a configuration file in the /etc/rsyslog.d/ directory:
    cron.* /var/log/cron
    The rsyslog daemon must be restarted for the changes to take effect:
    $ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204489'
  tag 'rid': 'SV-204489r744109_rule'
  tag 'stig_id': 'RHEL-07-021100'
  tag 'fix_id': 'F-4613r744108_fix'
  tag 'cci': ['CCI-000366']
  tag nist: ['CM-6 b']

  log_pkg_path = input('log_pkg_path')

  describe.one do
    describe command("grep cron #{log_pkg_path}") do
      its('stdout.strip') { should match(/^cron/) }
    end
    describe file(log_pkg_path.to_s) do
      its('content') { should match %r{^\*\.\* /var/log/messages\n?$} }
      its('content') { should_not match %r{^*.*\s+~$.*^*\.\* /var/log/messages\n?$}m }
    end
  end
end
