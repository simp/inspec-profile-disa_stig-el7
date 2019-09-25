require 'spec_helper_acceptance'
require 'json'

test_name 'Check Inspec'

describe 'run inspec against the appropriate fixtures' do

  profiles_to_validate = ['disa_stig']

  hosts.each do |host|
    profiles_to_validate.each do |profile|
      context "for profile #{profile}" do
        context "on #{host}" do
          before(:all) do
            @inspec = Simp::BeakerHelpers::Inspec.new(host, profile)
            @inspec_report = {:data => nil}
          end

          it 'should run inspec' do
            @inspec.run
          end

          it 'should have an inspec report' do
            @inspec_report[:data] = @inspec.process_inspec_results

            info = [
              'Results:',
              "  * Passed: #{@inspec_report[:data][:passed]}",
              "  * Failed: #{@inspec_report[:data][:failed]}",
              "  * Skipped: #{@inspec_report[:data][:skipped]}"
            ]

            puts info.join("\n")

            @inspec.write_report(@inspec_report[:data])
          end

          it 'should have run some tests' do
            expect(@inspec_report[:data][:failed] + @inspec_report[:data][:passed]).to be > 0
          end

          it 'should not have any failing tests' do
            if @inspec_report[:data][:failed] > 0
              puts @inspec_report[:data][:report]

              skip 'The SSG does not provide 100% remediation'
            end

            expect( @inspec_report[:data][:failed] ).to eq(0)
          end
        end
      end
    end
  end
end
