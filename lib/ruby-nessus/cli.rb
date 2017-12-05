require 'rubygems'
require 'ruby-nessus/ruby-nessus'
require 'ruby-nessus/log'
require 'optparse'

require 'pp'

module RubyNessus
  class CLI
    def initialize
      @file = nil
      @nessus_version = nil
      @args = []
    end

    def CLI.run
      self.new.run(*ARGV)
    end

    def run(*args)
      optparse(*args)

      Log.it 'Recess - Ruby-Nessus CLI'
      Log.it "Version: #{RubyNessus::VERSION}"
      Log.it

      RubyNessus::Parse.new("#{@file}") do |scan|
        Log.h1 'SCAN Metadata'
        Log.it
        Log.h2 'Scan Title', scan.title
        Log.h2 'Policy Title', scan.policy_title
        Log.it
        Log.h1 'SCAN Statistics'
        Log.it
        Log.h2 'Host Count', scan.host_count
        Log.h2 'Open Port Count', scan.open_ports_count

        unless scan.version == 1
          Log.h2 'TCP Count', scan.tcp_count
          Log.h2 'UDP Count', scan.udp_count
          Log.h2 'ICMP Count', scan.icmp_count
        end

        Log.it
        Log.h1 'EVENT Statistics'
        Log.it

        unless scan.version == 1
          Log.informational 'Informational Severity Count', scan.informational_severity_count
        end

        Log.low 'Low Severity Count', scan.low_severity_count
        Log.medium 'Medium Severity Count', scan.medium_severity_count
        Log.high 'High Severity Count', scan.high_severity_count
        Log.h3 'Total Event Count', scan.total_event_count
        Log.break
        Log.it! "Low Event Percentage: #{scan.event_percentage_for('low', true)}"
        Log.it! "Medium Event Percentage: #{scan.event_percentage_for('medium', true)}"
        Log.it! "High Event Percentage: #{scan.event_percentage_for('high', true)}"
        Log.it

        Log.h1 'HOSTS'
        Log.it

        scan.each_host do |host|
          Log.h2 'Hostname', host.hostname
          Log.h5 'IP Address:', host.ip

          unless scan.version == 1
            Log.h5 'Informational Count', host.informational_severity_count
            Log.h5 'Low Count', host.low_severity_count
            Log.h5 'Medium Count', host.medium_severity_count
            Log.h5 'High Count', host.high_severity_count
          end
          Log.it
        end

        Log.end
      end
    end

    protected

    def optparse(*args)
      opts = OptionParser.new
      opts.program_name = 'recess'
      opts.banner = "Recess #{RubyNessus::VERSION}"
      opts.separator 'usage: recess FILE [OPTIONS]'

      opts.on('-f', '--file FILE', 'The .nessus file to parse.') do |file|
        @file = file
      end

      opts.on('-f', '--file FILE', 'The .nessus file to parse.') do |file|
        @file = file
      end

      opts.on('-h', '--help', 'This help summary page.') do |help|
        Log.it opts
        Log.it
        exit -1
      end

      opts.on('-v', '--version', 'Recess Version.') do |version|
        Log.it RubyNessus::VERSION
        Log.it
        exit -1
      end

      begin
        @args = opts.parse!(args)
        @file ||= @args[0]
        if @file.nil?
          Log.it opts
          Log.it
          exit -1
        end
      rescue => e
        Log.error e.message
        Log.it opts
        Log.it
        exit -1
      end
    end
  end
end
