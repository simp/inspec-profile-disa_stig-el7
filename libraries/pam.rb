# encoding: utf-8

class Pam < Inspec.resource(1)
  attr_reader :lines

  # These are here for useful interfaces into the module stack based on
  # common searches
  attr_reader :services, :types, :modules

  name 'pam'

  supports platform: 'unix'

  desc 'Use the InSpec pam resource to test the given system pam configuration'
  example "
    # Query for a match:

    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512' }
    end

    # Query everything for a match without specific arguments
    # You can use a Ruby regexp match for everything except arguments

    describe pam('/etc/pam.d') do
      its('lines') { should match_pam_rule('.* .* pam_unix.so').without_args('nullok' }
    end

    # Query for multiple lines

    describe pam('/etc/pam.d/password-auth') do
      required_lines = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('lines') { should match_pam_ruiles(required_lines) }
    end

    # Query for multiple lines without any lines in between them

    describe pam('/etc/pam.d/password-auth') do
      required_lines = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('lines') { should match_pam_ruiles(required_lines).exactly }
    end
  "

  class PamError < StandardError; end

  def initialize(path = '/etc/pam.d')
    @path          = path
    @services      = {}
    @types         = {}
    @modules       = {}

    config_target = inspec.file(path)

    @lines         = Pam::Lines.new(config_target)

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

      lines = config_file.content.lines.map(&:strip).delete_if{|x| x =~ /^(\s*#.*|\s*)$/}
      service = nil
      unless @top_config
        service = config_file.basename
      end

      lines.each do |line|
        new_line = Pam::Line.new(line, {:service_name => service})

        unless new_line.type && new_line.control && new_line.module_path
          raise PamError, "Invalid PAM config found at #{config_file}"
        end

        @services[new_line.service] ||= []
        @services[new_line.service] << new_line

        @types[new_line.type] ||= []
        @types[new_line.type] << new_line

        @modules[new_line.module_path] ||= []
        @modules[new_line.module_path] << new_line

        @lines.push(new_line)
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

  class Lines < Array
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

    def first?(line, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      _line = Pam::Line.new(line, {:service_name => service_name})

      lines_of_type(_line.type, opts).first == _line
    end

    def last?(line, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      _line = Pam::Line.new(line, {:service_name => service_name})

      lines_of_type(_line.type, opts).last == _line
    end

    def lines_of_type(line_type, opts={:service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      if @services[service_name]
        @services[service_name].find_all do |l|
          l.type == line_type
        end
      else
        []
      end
    end

    def include?(lines, opts={:exact => false, :service_name => nil})
      raise PamError, 'opts must be a hash' unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      lines = Array(lines).map{|l| Pam::Line.new(l, {:service_name => service_name})}

      retval = false

      if opts[:exact]
        # This requires everything between the first and last rule to match
        # exactly

        first_entry = index(lines.first)
        last_entry = index(lines.last)

        if first_entry && last_entry
          retval = (self[first_entry..last_entry] == lines)
        end
      else
        # This match allows other rules between the two in question
        retval = (lines.select{|l| super(l)} == lines)
      end

      return retval
    end
    alias_method :match, :include?

    def include_exactly?(lines, opts={})
      include?(lines, opts.merge({:exact => true}))
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

  class Line
    attr_reader :to_s
    attr_reader :service, :silent, :type, :control, :module_path, :module_arguments

    def initialize(line, opts = {})
      @to_s = line.strip.gsub(/\s+/,' ')

      line_regex = <<-'EOM'
        # Start of Line
          ^
        # Ignore initial Whitespace
          \s*
        # Capture Silent Flag
          (?<silent>-)?
      EOM

      unless opts[:service_name]
        line_regex += <<-'EOM'
          # Capture Service
            (?<service_name>.+?)\s+
        EOM
      end

      line_regex += <<-'EOM'
        # Capture Type
          (?<type>.+?)\s+
        # Capture Control
          (?<control>(\[.+\]|.+?))\s+
        # Capture Module Path
          (?<module_path>.+?(\.so)?)
        # Capture Module Args
          (\s+(?<module_args>.+?))?
        # End of Line
          $
      EOM

      match_data = line.match(Regexp.new(line_regex, Regexp::EXTENDED))

      unless match_data
        raise PamError, "Invalid PAM configuraiton line: '#{line}'"
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
