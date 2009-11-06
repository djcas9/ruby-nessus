require 'ruby-nessus/host'
require 'ruby-nessus/event'

require 'nokogiri'

module Nessus
  attr_reader :file

  class XML

    def initialize(file, &block)
      @file = File.open(file)
      @xml = Nokogiri::XML.parse(@file.read)

      block.call(self) if block
    end

    def report_name
      @xml.xpath("//NessusClientData//Report//ReportName").inner_text
    end

    def start_time
      @xml.xpath("//NessusClientData//Report//StartTime").inner_text
    end

    def stop_time
      @xml.xpath("//NessusClientData//Report//StopTime").inner_text
    end

    def run_time
      # Need to fine duration from start and top times
      #DateTime.parse(stop_time)
    end

    def policy_name
      @xml.xpath("//NessusClientData//Report//policyName").inner_text
    end

    def policy_comments
      @xml.xpath("//NessusClientData//Report//policyComments").inner_text
    end

    def plugin_ids
      @plugin_ids = []
      @xml.xpath("//PluginSelection").last.text.split(';').each do |id|
        @plugin_ids << id
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

    def hosts_with(options={}, &block)
      @blah = []
      @xml.xpath("//ReportHost").each do |host|
        block.call(Host.new(host)) if block && Host.new(host).event_count >= 10
      end
      @blah
    end

    def host_count
      hosts.size
    end

    def self.number_of_open_ports
      #@xml.xpath("//ReportHost//HostName" => host).to_s
      #list.each { |port| yield port } if block_given?
    end

    def ports
      @ports = {}
    end

    def plugins
      # get elements with attribute:
      @plugins = []
      @xml.xpath("//pluginName").each do |x|
        @plugins << x.text unless x.text == ""
      end
      return @plugins.sort.uniq!
    end

    def ports
      @xml.xpath("//ReportItem//port").inner_text
    end

    def informational_severity_count
      return count_severity[:informational].to_i
    end

    def high_severity_count
      return count_severity[:high].to_i
    end

    def medium_severity_count
      return count_severity[:medium].to_i
    end

    def low_severity_count
      return count_severity[:low].to_i
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

    def find_by_hostname(options={}, &block)
      @xml.xpath('//ReportHost[HostName]').each do |host|
        next unless host.inner_text.match(options[:hostname])
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

# <ReportHost>
#== HostName
#== startTime
#== stopTime
#== netbios_name
#== mac_addr
#== dns_name
#== os_name
#== num_ports
#== num_lo
#== num_med
#== num_hi
## <ReportItem> ## may or may NOT have a reportitem node
####== port
####== severity
####== pluginID
####== pluginName
####== data
## </ReportItem>
# </ReportHost>
