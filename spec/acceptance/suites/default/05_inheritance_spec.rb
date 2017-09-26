require 'spec_helper_acceptance'
require 'json'

test_name 'Validate Inspec Inheritance'

describe 'Ensure that inheritance works' do

  profiles_to_validate = ['inheritance_test']

  hosts.each do |host|
    profiles_to_validate.each do |profile|
      context "for profile #{profile}" do
        context "on #{host}" do
          before(:all) do
            @inspec = Simp::BeakerHelpers::Inspec.new(host, profile)
          end

          it 'should run inspec' do
            @inspec.run
          end

          it 'should have an inspec report' do
            inspec_report = @inspec.process_inspec_results

            if inspec_report[:failed] > 0
              puts inspec_report[:report]
            end
          end
        end
      end
    end
  end
end
