# Variables:
#
# SIMP_GEM_SERVERS | a space/comma delimited list of rubygem servers
gem_sources = ENV.key?('SIMP_GEM_SERVERS') ? ENV['SIMP_GEM_SERVERS'].split(/[, ]+/) : ['https://rubygems.org']

gem_sources.each { |gem_source| source gem_source }

gem 'rake'
gem 'simp-rake-helpers', '~> 5.6'
gem 'simp-beaker-helpers', '~> 1.13'
gem 'beaker-rspec'
gem 'highline'
gem 'kitchen-puppet'
gem 'kitchen-inspec'
gem 'kitchen-vagrant'
gem 'inspec'
gem 'librarian-puppet'
