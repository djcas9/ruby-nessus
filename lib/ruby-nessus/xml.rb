require 'ruby-nessus/host'
require 'ruby-nessus/event'

require 'nokogiri'

module Nessus
  # File to parse
  attr_reader :file

  class XML

    #
    # Creates a new .Nessus (XML) object to be parser
    #
    # @param [String] file The Nessus xml results file to parse.
    #
    # @yield [prog] If a block is given, it will be passed the newly
    #               created XML object.
    # @yieldparam [Program] prog The newly created program object.
    #
    # @raise [ProgramNotFound] Specifies the given path was not a valid
    #                          file.
    #
    # @example
    #   Program.new('/usr/bin/ls')
    #
    def initialize(file, &block)
      @file = File.open(file)
      @xml = Nokogiri::XML.parse(@file.read)

      block.call(self) if block
    end

    def report_name
      @report_name ||= @xml.xpath("//NessusClientData//Report//ReportName").inner_text
    end

    def start_time
      @start_time ||= @xml.xpath("//NessusClientData//Report//StartTime").inner_text
    end

    def stop_time
      @stop_time ||= @xml.xpath("//NessusClientData//Report//StopTime").inner_text
    end

    def run_time
      # Need to fine duration from start and top times
      #DateTime.parse(stop_time)
    end

    def policy_name
      @policy_name ||= @xml.xpath("//NessusClientData//Report//policyName").inner_text
    end

    def policy_comments
      @policy_comments ||= @xml.xpath("//NessusClientData//Report//policyComments").inner_text
    end

    def plugin_ids
      unless @plugin_ids
        @plugin_ids = []

        @xml.xpath("//PluginSelection").last.text.split(';').each do |id|
          @plugin_ids << id
        end
      end

      @plugin_ids
    end

    def hosts(&block)
      hosts = []
      @xml.xpath("//ReportHost").each do |host|
        hosts << host.at('HostName').inner_text if host.at('HostName').inner_text
        block.call(Host.new(host)) if block
      end
      hosts
    end

    def host_count
      hosts.size
    end

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

    def unique_ports
      @ports = []
      @xml.xpath("//ReportItem//port").each do |port|
        @ports << port.inner_text
      end
      @ports.sort.uniq!
    end

    def informational_severity_count
      count_severity[:informational].to_i
    end

    def high_severity_count
      count_severity[:high].to_i
    end

    def medium_severity_count
      count_severity[:medium].to_i
    end

    def low_severity_count
      count_severity[:low].to_i
    end

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
      count = {}
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

      count[:informational] = @informational
      count[:low] = @low
      count[:medium] = @medium
      count[:high] = @high
      count[:all] = (@informational + @low + @medium + @high)

      return count
    end

  end
end
