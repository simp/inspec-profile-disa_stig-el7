# Variables:
#
# SIMP_GEM_SERVERS | a space/comma delimited list of rubygem servers
gem_sources = ENV.key?('SIMP_GEM_SERVERS') ? ENV['SIMP_GEM_SERVERS'].split(/[, ]+/) : ['https://rubygems.org']

gem_sources.each { |gem_source| source gem_source }

gem 'rake'
# For the fixtures.yml 'target' path functionality
gem 'simp-rake-helpers', '~> 4.0'
gem 'puppetlabs_spec_helper', :git => 'https://github.com/puppetlabs/puppetlabs_spec_helper', :ref => 'master'
gem 'simp-beaker-helpers', '>= 1.10.5', '< 2.0.0'
gem 'beaker-rspec'
gem 'highline'
gem 'pry'
gem 'kitchen-puppet'
gem 'kitchen-inspec'
gem 'kitchen-vagrant'
gem 'inspec'
gem 'librarian-puppet'
