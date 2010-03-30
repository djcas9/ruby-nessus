require 'rubygems'
require 'ruby-nessus/nessus'
require 'ruby-nessus/log'
require 'optparse'

require 'pp'

module Nessus
  
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

    end

    protected

      def optparse(*args)
        opts = OptionParser.new
        opts.program_name = "recess"
        opts.banner = "Recess #{Nessus::VERSION}"
        opts.separator "usage: recess FILE [OPTIONS]"

        opts.on('-f','--file FILE','The .nessus file to parse.') do |file|
          @file = file
        end

        opts.on('-h','--help','This help summary page.') do |help|
          Log.it opts
          exit -1
        end

        opts.on('-v','--version','Version number') do |version|
          Log.it Nessus::VERSION
          exit -1
        end

        begin
          @args = opts.parse!(args)
          @file ||= @args[0]
          if @file.nil?
            Log.it opts
            exit -1
          end
        rescue  => e
          Log.error e.message
          Log.it opts
          exit -1
        end
      end

  end
end
