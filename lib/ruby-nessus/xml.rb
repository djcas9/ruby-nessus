require 'ruby-nessus/host'
require 'ruby-nessus/event'
require 'nokogiri'
require 'time'

module Nessus
  # File to parse
  attr_reader :file

  class XML

    # Creates a new .Nessus (XML) object to be parser
    # @param [String] file The Nessus xml results file to parse.
    # @yield [prog] If a block is given, it will be passed the newly
    #               created XML object.
    # @yieldparam [XML] prog The newly created XML object.
    # @example
    #   Nessus::XML.new(nessus_scan_file) do |scan|
    #     scan.report_name
    #   end
    def initialize(file, &block)

      @file = File.open(file)
      @xml = Nokogiri::XML.parse(@file.read)

      block.call(self) if block
    end
    
    # Return the nessus report title.
    # @return [String]
    #   The Nessus Report Title
    def report_name
      @report_name ||= @xml.xpath("//NessusClientData//Report//ReportName").inner_text
    end
    
    # Return the scan start time. Example: Fri Apr  3 23:36:54 2009
    # @return [DateTime]
    #   The Nessus Scan Start Time
    def start_time
      @start_time = @xml.xpath("//NessusClientData//Report//StartTime").inner_text
    end

    # Return the scan stop time. Example: Fri Apr  3 23:36:54 2009
    # @return [DateTime]
    #   The Nessus Scan Stop Time
    def stop_time
      @stop_time = @xml.xpath("//NessusClientData//Report//StopTime").inner_text
    end

    # Return the scan run time. Example: 2 hours 5 minutes and 16 seconds
    # @return [String]
    #   The Nessus Scan Run Time
    def run_time
      h = ("#{Time.parse(stop_time).strftime('%H').to_i - Time.parse(start_time).strftime('%H').to_i}").gsub('-', '')
      m = ("#{Time.parse(stop_time).strftime('%M').to_i - Time.parse(start_time).strftime('%M').to_i}").gsub('-', '')
      s = ("#{Time.parse(stop_time).strftime('%S').to_i - Time.parse(start_time).strftime('%S').to_i}").gsub('-', '')
      return "#{h} hours #{m} minutes and #{s} seconds"
    end

    # Return the nessus scan policy name. When creating a nessus policy this is usually the title field.
    # @return [String]
    #   The Nessus Scan Policy Name
    def policy_name
      @policy_name ||= @xml.xpath("//NessusClientData//Report//policyName").inner_text
    end

    # Return the nessus scan policy comments. This is the description field when creating a new policy with the Nessus GUI client.
    # @return [String]
    #   The Nessus Scan Policy Comments
    def policy_comments
      @policy_comments ||= @xml.xpath("//NessusClientData//Report//policyComments").inner_text
    end

    # Returns and array of the plugin ids userd for the passed .nessus scan.
    # @return [Array]
    #   The Nessus Scan Plugin Ids
    def plugin_ids
      unless @plugin_ids
        @plugin_ids = []

        @xml.xpath("//PluginSelection").last.text.split(';').each do |id|
          @plugin_ids << id
        end
      end

      @plugin_ids
    end
    
    # Returns and array of the plugin names userd for the passed .nessus scan.
    # @return [Array]
    #   The Nessus Scan Plugin Names
    def plugins
      unless @plugins
        # get elements with attribute:
        @plugins = []

        @xml.xpath("//pluginName").each do |x|
          @plugins << x.inner_text unless x.inner_text.empty?
        end

        @plugins.uniq!
        @plugins.sort!
      end

      return @plugins
    end

    # Creates a new Host object to be parser
    # @yield [prog] If a block is given, it will be passed the newly
    #               created Host object.
    # @yieldparam [XML] prog The newly created Host object.
    # @example
    #   scan.hosts do |host|
    #     puts host.hostname
    #   end
    def hosts(&block)
      hosts = []
      @xml.xpath("//ReportHost").each do |host|
        hosts << host.at('HostName').inner_text if host.at('HostName').inner_text
        block.call(Host.new(host)) if block
      end
      hosts
    end

    # Return the nessus scan host count.
    # @return [Integer]
    #   The Nessus Scan Host Count
    def host_count
      hosts.size
    end

    # Retunrs an array of all unique ports. 
    # @return [Array]
    # @example
    #   scan.unique_ports #=> 234
    def unique_ports
      unless @unique_ports
        @unique_ports = []
        @xml.xpath("//ReportItem//port").each do |port|
          @unique_ports << port.inner_text
        end
        @unique_ports.uniq!
        @unique_ports.sort!
      end
    end

    # Return the informational severity count.
    # @return [Integer]
    #   The Informational Severity Count
    def informational_severity_count
      count_severity[:informational].to_i
    end

    # Return the High severity count.
    # @return [Integer]
    #   The High Severity Count
    def high_severity_count
      count_severity[:high].to_i
    end

    # Return the Medium severity count.
    # @return [Integer]
    #   The Medium Severity Count
    def medium_severity_count
      count_severity[:medium].to_i
    end

    # Return the Low severity count.
    # @return [Integer]
    #   The Low Severity Count
    def low_severity_count
      count_severity[:low].to_i
    end

    # Return the Total severity count. [high, medium, low, informational]
    # @return [Integer]
    #   The Total Severity Count
    def total_event_count
      count_severity[:all].to_i
    end

    # Return the Total severity count.
    # @param [String] severity the severity in which to calculate percentage for.
    # @param [Boolean] round round the result to the nearest whole number.
    # @raise [ExceptionClass] One of the following severity options must be passed. [high, medium, low, informational, all]
    # @return [Integer]
    #   The Percentage Of Events For A Passed Severity
    # @example
    #   scan.event_percentage_for("low", true) #=> 11%
    def event_percentage_for(type, round_percentage=false)
      @sc ||= count_severity
      if %W(high medium low informational all).include?(type)
        c = @sc[:"#{type}"].to_f
        t = @sc[:all].to_f
        c1 = (c / t) * 100
        if round_percentage
          return "#{c1.round}"
        else
          return "#{c1}"
        end
      else
        raise "Error: #{type} is not an acceptable severity. Possible options include: all, high, medium, low and informational."
      end
    end

    def find_by_hostname(hostname, &block)
      raise "Error: hostname can't be blank." if hostname.blank?
      @xml.xpath('//ReportHost[HostName]').each do |host|
        next unless host.inner_text.match(hostname)
        block.call(Host.new(host)) if block
      end
    end

    private

    def count_severity
      unless @count
        @count = {}
        @informational = 0
        @low = 0
        @medium = 0
        @high = 0
        @all = 0

        @xml.xpath("//ReportItem//severity").each do |s|
          case s.inner_text.to_i
          when 0
            @informational += 1
          when 1
            @low += 1
          when 2
            @medium += 1
          when 3
            @high += 1
          end
        end

        @count[:informational] = @informational
        @count[:low] = @low
        @count[:medium] = @medium
        @count[:high] = @high
        @count[:all] = (@informational + @low + @medium + @high)
      end

      return @count
    end

  end
end
