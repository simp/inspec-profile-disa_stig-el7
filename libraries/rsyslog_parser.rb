# encoding: utf-8
# author: Matthew Dromazos

require 'parslet'

# only designed for sysklogd formatted config files for now:
class RsyslogParser < Parslet::Parser
  root :selectors
  
  rule(:selectors) { selector.repeat }
  
  rule(:selector) {
    (comment |
    local_selector |
    remote_selector | 
    database_selector)  >> 
    newline.repeat
  }
    
  rule(:local_selector) { 
    (facility >> 
    dot >> 
    priority >> 
    space.repeat >> 
    local_destination).as(:local_selector)
  }
  
  rule(:remote_selector) { 
    (facility >> 
    dot >> 
    priority >> 
    space.repeat >> 
    protocol >>
    remote_destination >>
    (colon >>
    port).maybe).as(:remote_selector)
  }
  
  rule(:database_selector) { 
    (facility >> 
    dot >> 
    priority >> 
    space.repeat >> 
    str('>') >>
    dbhost >>
    dbname >>
    dbuser >>
    dbpassword).as(:database_selector)
  }
  
  rule(:protocol) { (str('@').repeat(1,2)).as(:protocol) }
  rule(:local_destination) { (str('@').absent? >> str('>').absent? >> (newline.absent? >> any).repeat).as(:destination) }
  rule(:remote_destination) { (((colon.absent? >> newline.absent?) >> any).repeat).as(:destination) }
  rule(:facility) { ((dot.absent? >> any).repeat).as(:facility) }
  rule(:priority) { ((space.absent? >> any).repeat).as(:priority) }
  rule(:port) { (((newline.absent? >> semicolon.absent?) >> match['0-9']).repeat).as(:port) }
  rule(:comment) { str('#') >> (match["\n\r"].absent? >> any).repeat }
  
  # Rules for database selectors
  rule(:dbhost) { ((comma.absent? >> any).repeat).as(:dbhost) >> comma }
  rule(:dbname) { ((comma.absent? >> any).repeat).as(:dbname) >> comma }
  rule(:dbuser) { ((comma.absent? >> any).repeat).as(:dbuser) >> comma }
  rule(:dbpassword) { ((newline.absent? >> any).repeat).as(:dbpassword) }


  rule(:space)   { match('\s+') }
  rule(:newline) { match['\n'] }
  rule(:dot) { str('.') }
  rule(:comma) { str(',') }
  rule(:colon) { str(':') }
  rule(:semicolon) { str(';') }

end

class RsyslogTransform < Parslet::Transform
  rule(local_selector: subtree(:local_selector)) { {selector_type: 'local'}.merge(local_selector.each {|key, val| local_selector[key] = val.to_s}) }
  rule(remote_selector: subtree(:remote_selector)) { {selector_type: 'remote'}.merge(remote_selector.each {|key, val| remote_selector[key] = val.to_s}) }
  rule(database_selector: subtree(:database_selector)) { {selector_type: 'database'}.merge(database_selector.each {|key, val| database_selector[key] = val.to_s}) }
end

class RsyslogConfig
  def self.parse(content)
    lex = RsyslogParser.new.parse(content)
    tree = RsyslogTransform.new.apply(lex)
    tree = transform_protocol(tree)
  rescue Parslet::ParseFailed => err
    puts err.parse_failure_cause.ascii_tree
    raise "Failed to parse Rsyslog config: #{err}"
  end
  
  def self.transform_protocol(tree)
    tree.each_with_index do |hash,i|
      if hash.has_key?(:protocol)
        tree[i][:protocol] = (tree[i][:protocol] == '@' ? 'udp' : 'tcp')
      end
    end
  end
end
