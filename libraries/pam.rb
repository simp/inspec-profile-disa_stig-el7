# encoding: utf-8

class Pam < Inspec.resource(1)
  # These are aliases for one another
  attr_reader :rules, :lines

  # These are here for useful interfaces into the module stack based on
  # common searches
  attr_reader :services, :types, :modules

  name 'pam'

  supports platform: 'unix'

  desc 'Use the InSpec pam resource to test the given system pam configuration'
  example "
    # Query for a match:

    describe pam('/etc/pam.d/system-auth') do
      its('rules') { should match_pam_rule('password sufficient pam_unix.so sha512' }
    end

    # Query everything for a match without specific arguments
    # You can use a Ruby regexp match for everything except arguments

    describe pam('/etc/pam.d') do
      its('rules') { should match_pam_rule('.* .* pam_unix.so').without_args('nullok' }
    end

    # Query for multiple lines

    describe pam('/etc/pam.d/password-auth') do
      required_rules = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('rules') { should match_pam_ruiles(required_rules) }
    end

    # Query for multiple rules without any rules in between them

    describe pam('/etc/pam.d/password-auth') do
      required_rules = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('rules') { should match_pam_ruiles(required_rules).exactly }
    end
  "

  class PamError < StandardError; end

  def initialize(path = '/etc/pam.d')
    @path          = path
    @services      = {}
    @types         = {}
    @modules       = {}

    config_target = inspec.file(path)

    @rules         = Pam::Rules.new(config_target)
    @lines         = @rules

    @top_config = false
    if path.strip == '/etc/pam.conf'
      @top_config = true
    end

    parse_content(config_target)
  end

  def parse_content(path)
    config_files = Array(path)

    if path.directory?
      config_files = inspec.bash("ls #{path}/*").stdout.lines.map{|f| inspec.file(f.strip) }
    end

    config_files.each do |config_file|
      next unless config_file.content

      rules = config_file.content.gsub("\\\n",' ').lines.map(&:strip).delete_if do |line|
        line  =~ /^(\s*#.*|\s*)$/
      end

      service = nil
      unless @top_config
        service = config_file.basename
      end

      rules.each do |rule|
        new_rule = Pam::Rule.new(rule, {:service_name => service})

        unless new_rule.type && new_rule.control && new_rule.module_path
          raise PamError, "Invalid PAM config found at #{config_file}"
        end

        @services[new_rule.service] ||= []
        @services[new_rule.service] << new_rule

        @types[new_rule.type] ||= []
        @types[new_rule.type] << new_rule

        @modules[new_rule.module_path] ||= []
        @modules[new_rule.module_path] << new_rule

        @rules.push(new_rule)
      end
    end
  end

  def to_s
    "PAM Config[#{@path}]"
  end

  def service(service_name)
    @services[service_name]
  end

  def type(type_name)
    @types[type_name]
  end

  def module(module_name)
    @modules[module_name]
  end

  class Rules < Array
    def initialize(config_target)
      @config_target = config_target
    end

    def services
      self.collect{|l| l.service}.sort.uniq
    end

    def service
      svcs = self.collect{|l| l.service}.sort.uniq
      if svcs.length > 1
        raise PamError, %(More than one service found: '[#{svcs.join("', '")}]')
      end

      svcs.first
    end

    def first?(rule, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      _rule = Pam::Rule.new(rule, {:service_name => service_name})

      rules_of_type(_rule.type, opts).first == _rule
    end

    def last?(rule, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      _rule = Pam::Rule.new(rule, {:service_name => service_name})

      rules_of_type(_rule.type, opts).last == _rule
    end

    def rules_of_type(rule_type, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      if @services[service_name]
        @services[service_name].find_all do |l|
          l.type == rule_type
        end
      else
        []
      end
    end

    def include?(rules, opts={:exact => false, :service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      rules = Array(rules).map{|l| Pam::Rule.new(l, {:service_name => service_name})}

      retval = false

      if opts[:exact]
        # This requires everything between the first and last rule to match
        # exactly

        first_entry = index(rules.first)
        last_entry = index(rules.last)

        if first_entry && last_entry
          retval = (self[first_entry..last_entry] == rules)
        end
      else
        # This match allows other rules between the two in question
        retval = (rules.select{|l| super(l)} == rules)
      end

      return retval
    end
    alias_method :match, :include?

    def include_exactly?(rules, opts={})
      include?(rules, opts.merge({:exact => true}))
    end
    alias_method :match_exactly, :include_exactly?

    def to_a
      self.map{|l| l.to_s}
    end

    def to_s
      to_a.join("\n")
    end

    private

    def get_service_name(svc_name = nil)
      return svc_name if svc_name

      if !svc_name && @config_target.directory?
        raise PamError, 'You must pass ":service_name" as an option!'
      else
        return @config_target.basename
      end
    end
  end

  class Rule 
    attr_reader :to_s
    attr_reader :service, :silent, :type, :control, :module_path, :module_arguments

    def initialize(rule, opts = {})
      @to_s = rule.strip.gsub(/\s+/,' ')

      rule_regex = <<-'EOM'
        # Start of Rule
          ^
        # Ignore initial Whitespace
          \s*
        # Capture Silent Flag
          (?<silent>-)?
      EOM

      unless opts[:service_name]
        rule_regex += <<-'EOM'
          # Capture Service
            (?<service_name>.+?)\s+
        EOM
      end

      rule_regex += <<-'EOM'
        # Capture Type
          (?<type>.+?)\s+
        # Capture Control
          (?<control>(\[.+\]|.+?))\s+
        # Capture Module Path
          (?<module_path>.+?(\.so)?)
        # Capture Module Args
          (\s+(?<module_args>.+?))?
        # End of Rule
          $
      EOM

      match_data = rule.match(Regexp.new(rule_regex, Regexp::EXTENDED))

      unless match_data
        raise PamError, "Invalid PAM configuraiton rule: '#{rule}'"
      end

      @service          = opts[:service_name] ? opts[:service_name] : match_data[:service_name]
      @silent           = match_data[:silent] == '-'
      @type             = match_data[:type]
      @control          = match_data[:control]
      @module_path      = match_data[:module_path]
      @module_arguments = match_data[:module_args] ? match_data[:module_args].strip.split(/\s+/) : []
    end

    def ==(to_cmp)
      to_cmp = Pam::Line.new(to_cmp) if to_cmp.is_a?(String)

      self.class == to_cmp.class &&
        @service.match(Regexp.new("^#{to_cmp.service}$")) &&
        @type.match(Regexp.new("^#{to_cmp.type}$")) &&
        @control.match(Regexp.new("^#{to_cmp.control.gsub(/(\[|\])/, '\\\\\\1')}$")) &&
        @module_path.match(Regexp.new("^#{to_cmp.module_path}$")) &&
        (to_cmp.module_arguments - @module_arguments).empty?
    end
    alias_method :eql?, :==
  end
end
