# encoding: utf-8

require 'parser'
require 'file_reader'
require 'syslog_ng_parser'

class SyslogNGConf < Inspec.resource(1)
  name 'syslog_ng_conf'
  supports platform: 'linux'
  desc ''
  example "
    
  "

  attr_reader :params

  include CommentParser
  include FileReader

  DEFAULT_UNIX_PATH = '/etc/syslog-ng/syslog-ng.conf'.freeze

  def initialize(rsyslog_path = nil)
    @path = rsyslog_path || DEFAULT_UNIX_PATH
    content = read_file_content(@path)
    return skip_resource 'The `rsyslog_conf` resource is not supported on Windows.' if inspec.os.windows?
    @params = parse_syslog_ng(content)
  end
  
  def sending_to_remote_server
    logs = @params.select {|x| x.type == 'log'}
    remotes = @params.select {|x| x.type == 'destination' && !x.body.detect{|y| y.name == 'tcp' || y.name == 'udp'}.nil?}
    logs.each do |log|
      dest_logs = log.body.select{|x| x.name == 'destination'}
      dest_logs.each do |dest_log|
        remotes.each do |remote|
          return true if remote.id == dest_log.parameters[0]
        end
      end
    end
    return false
  end
  alias sending_to_remote_server? sending_to_remote_server
  
  private
  
  def parse_syslog_ng(content)
    data = SyslogNGConfig.parse(content)
  rescue StandardError => _
    raise "Cannot parse syslog-ng config in #{@path}."
  end
end
