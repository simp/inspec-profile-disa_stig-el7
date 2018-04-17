# encoding: utf-8

require 'utils/parser'
require 'utils/file_reader'
require 'utils/rsyslog_parser'

# STABILITY: Experimental
# This resouce needs a proper interace to the underlying data, which is currently missing.
# Until it is added, we will keep it experimental.
class RsyslogConf < Inspec.resource(1)
  name 'rsyslog_conf'
  supports platform: 'linux'
  desc 'The rsyslog_conf resource is used to test where rsyslog is configured to send syslog messags to.
        rsyslog can send messages to a local machine file, a database on the server, or to a remote server'
  example "
    # Test that rsyslog is sending syslog messages to a remote server
    describe rsyslog_conf('etc/rsyslog.conf') do
      it { should be_send_to_remote_server }
    end
  "

  attr_reader :selectors

  include CommentParser
  include FileReader

  DEFAULT_UNIX_PATH = '/etc/rsyslog.conf'.freeze
  
  filter = FilterTable.create
  filter.add_accessor(:where)
        .add(:selector_type, field: :selector_type)
        .add(:facilities, field: :facility)
        .add(:priorities, field: :priority)
        .add(:protocols, field: :protocol)
        .add(:destinations, field: :destination)
        .add(:ports, field: :port)
        .add(:dbhosts, field: :dbhost)
        .add(:dbnames, field: :dbname)
        .add(:dbusers, field: :dbuser)
        .add(:dbpasswords, field: :dbpassword)
  filter.connect(self, :selectors)

  def initialize(rsyslog_path = nil)
    @path = rsyslog_path || DEFAULT_UNIX_PATH
    content = read_file_content(@path)
    return skip_resource 'The `rsyslog_conf` resource is not supported on Windows.' if inspec.os.windows?
    parse_rsyslog(content)
  end
  
  # Matcher to test if there is any selectors that go to a remote system.
  def sending_to_remote_server(opts = {})
    !@selectors[:remote_selectors].empty?
    @selectors.include?({facility: facility, priority: priority, server: server, port: port}) if opts != {}
  end
  
  private
  
  def parse_rsyslog(content)
    @selectors = RsyslogConfig.parse(content)
  rescue StandardError => _
    raise "Cannot parse Rsyslog config in #{@path}."
  end
end
