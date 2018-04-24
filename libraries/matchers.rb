# encoding: utf-8

RSpec::Matchers.define :match_pam_rule do |expected|
  match do |actual|
    retval = false
    actual_munge = {}

    @expected = expected.to_s

    if @args
      catch :stop_searching do
        actual.services.each do |service|
          expected_line = Pam::Line.new(expected, {:service_name => service})

          potentials = actual.find_all do |line|
            !line.module_arguments.empty? && (line == expected_line)
          end

          if potentials && !potentials.empty?
            actual_munge[service] ||= []
            actual_munge[service] += potentials.map(&:to_s)

            potentials.each do |potential|
              Array(@args).each do |args|
                if @negate_args_match
                  throw :stop_searching if !potential.module_arguments.join(' ').match(args).nil?
                else
                  retval = !potential.module_arguments.join(' ').match(args).nil?
                end

                throw :stop_searching if retval
              end
            end
          end
        end
      end
    else
      retval = actual.include?(expected, {:service_name => actual.service})
    end

    if actual_munge.empty?
      @actual = actual.to_s
    elsif actual_munge.keys.length == 1
      @actual = actual_munge.values.flatten.join("\n")
    else
      @actual = actual_munge.map do |service, lines|
        lines.map do |line|
          service + ' ' + line
        end
      end.flatten.join("\n")
    end

    retval
  end

  diffable

  chain :with_args do |args|
    @args = args
  end

  chain :without_args do |args|
    @args = args
    @negate_args_match = true
  end

  description do
    res = "include #{expected}"
    if @negate_args_match
      res += " without #{@args}" unless @args.nil?
    else
      res += " with #{@args}" unless @args.nil?
    end
    res
  end
end

RSpec::Matchers.define :match_pam_rules do |expected|
  match do |actual|
    @expected = expected.to_s
    @actual = actual.to_s

    if @exactly && actual.respond_to?(:include_exactly?)
      actual.include_exactly?(expected)
    else
      actual.include?(expected)
    end
  end

  diffable

  chain :exactly do
    @exactly = true
  end

  description do
    res = "include #{expected}"
    res += ' exactly' unless @exactly.nil?
    res
  end
end
