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

    def host_count
      hosts.size
    end

    def plugins
      # get elements with attribute:
      @plugins = []
      @xml.xpath("//pluginName").each do |x|
        @plugins << x.text unless x.text == ""
      end
      return @plugins.sort.uniq!
    end

    def unique_ports
      @ports = []
      @xml.xpath("//ReportItem//port").each do |port|
        @ports << port.inner_text
      end
      @ports.sort.uniq!
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

    def find_by_hostname(hostname, &block)
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

  class Host
    attr_reader :host

    def initialize(host)
      @host = host

    end

    def hostname
      @host.at('HostName').inner_text
    end

    def start_time
      @host.at('startTime').inner_text
    end

    def stop_time
      @host.at('stopTime').inner_text
    end

    def netbios_name
      @host.at('netbios_name').inner_text
    end

    def mac_addr
      @host.at('mac_addr').inner_text
    end

    def dns_name
      @host.at('dns_name').inner_text
    end

    def os_name
      @host.at('os_name').inner_text
    end

    def scanned_ports
      false_if_zero(@host.at('num_ports').inner_text.to_i)
    end

    def informational_events
      @host.at('num_lo').inner_text.to_i
    end

    def low_severity_events
      @host.at('num_lo').inner_text.to_i
    end

    def medium_severity_events
      @host.at('num_med').inner_text.to_i
    end

    def high_severity_events(&block)
      @host.xpath("//ReportItem").each do |event|
        next if event.at('severity').inner_text.to_i != 3
        block.call(Event.new(event)) if block
      end
      @host.at('num_hi').inner_text.to_i
    end

    def event_count
      (informational_events + low_severity_events + medium_severity_events + high_severity_events).to_i
    end

    def events(&block)
      events = {}
      @host.xpath("//ReportItem").each do |event|
        events[:port] = event.at('port').inner_text
        events[:severity] = event.at('severity').inner_text.to_i
        events[:pluginID] = event.at('pluginID').inner_text.to_i
        events[:pluginName] = event.at('pluginName').inner_text
        events[:data] = event.at('data').inner_text unless event.at('data').nil?
        block.call(Event.new(event)) if block
      end
      events
    end

  end

  class Event
    attr_reader :event

    def initialize(event)
      @event = event
    end

    def port
      # Example: "ncube-lm (1521/tcp)"
      @port = @event.at('port').inner_text

      @port.instance_eval do
        @p = self.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
        def port_type
          if @p
            @p[1].strip unless @p[1].strip.nil?
          else
            false
          end
        end
        def port_service
          if @p
            @p[2].strip unless @p[2].strip.nil?
          else
            false
          end
        end
        def port_proto
          if @p
            @p[3].strip unless @p[3].nil?
          else
            false
          end
        end

      end

      return @port
    end

    def severity
      @severity = @event.at('severity').inner_text.to_i
      return @severity
    end

    def plugin_id
      @event.at('pluginID').inner_text.to_i
    end

    def plugin_name
      i = @event.at('pluginName').inner_text
      unless (i == "")
        return @event.at('pluginName').inner_text || "N/A"
      end
      false
    end
    alias name plugin_name

    def data
      @event.at('data').inner_text
    end
    alias output data

  end

end
