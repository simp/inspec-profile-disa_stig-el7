require 'spec_helper_acceptance'
require 'json'

test_name 'Remediate via SSG'

# Disclaimer:
#
# This is for something to test the policies against while testing
#
# The remediations in the SSG are almost certainly going to be different from
# those in the SIMP framework since SIMP is built as a composable system and
# not a monolithic 'lockdown'.
#
describe 'Use the SCAP Security Guide to remediate the system' do
  hosts.each do |host|
    context "on #{host}" do
      before(:all) do
        @ssg = Simp::BeakerHelpers::SSG.new(host)
      end

      it 'should remediate the system against the SSG' do

        # Were accepting all exit codes here because there have occasionally been
        # failures in the SSG content and we're not testing that.

        @ssg.remediate(%(xccdf_org.ssgproject.content_profile_stig-#{@ssg.profile_target}-disa))
      end
    end
  end
end
