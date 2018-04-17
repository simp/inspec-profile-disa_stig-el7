# encoding: utf-8
# author: Matthew Dromazos

require 'parslet'

class SyslogNGParser < Parslet::Parser
  root :beginning
  # only designed for rabbitmq config files for now:
  rule(:beginning) { str('@') >> (match["\n\r"].absent? >> any).repeat >> outermost}
  rule(:outermost) { filler? >> section.repeat }

  rule(:filler?) { one_filler.repeat }
  rule(:one_filler) { match('\s+') | match["\n"] | comment }
  rule(:space)   { match('\s+') }
  rule(:comment) { str('#') >> (match["\n\r"].absent? >> any).repeat }

  rule(:parameter) {
    (identifier >>  str(')').maybe >> options.as(:args)).as(:parameter) >> str(');') >> filler?
  }

  rule(:identifier) {
    ((match['\s{('].absent? >> match['\S']).repeat).as(:identifier) >> space.repeat
  }
  
  rule(:option) {
    ((match['\s'].absent? >> str(');').absent? >> any) >> (
      match['\s'].absent? >> str(');').absent? >> any
    ).repeat).as(:option) >> space.repeat
  }

  rule(:options) {
    option.repeat >> space.repeat
  }

  rule(:section) {
    identifier.as(:type) >> filler? >> identifier >> str('{') >> filler? >> parameter.repeat(1).as(:parameters) >> str('};') >> filler?
  }
end

class SyslogNGTransform < Parslet::Transform
  Group = Struct.new(:type, :id, :body)
  Option = Struct.new(:name, :parameters)
  
  rule(type: { identifier: simple(:x) }, identifier: simple(:y), parameters: subtree(:z)) { Group.new(x.to_s, y, z) }
  rule(type: { identifier: simple(:x) }, identifier: sequence(:y), parameters: subtree(:z)) { Group.new(x.to_s, nil, z) }
  rule(parameter: { identifier: simple(:x), args: subtree(:y) }) { Option.new(x.to_s, y) }
  rule(option: simple(:x)) { x.to_s }
end

class SyslogNGConfig
  def self.parse(content)
    lex = SyslogNGParser.new.parse(content)
    puts lex
    tree = SyslogNGTransform.new.apply(lex)
  rescue Parslet::ParseFailed => err
    puts err.parse_failure_cause.ascii_tree
    raise "Failed to parse Syslog-NG config: #{err}"
  end
end
