module Nessus
  attr_reader :file

  class XML

    def initialize(file, &block)
      @file = File.open(file)
      @xml = Nokogiri::XML.parse(@file.read)

      block.call(self) if block
    end

    def report_name
      @xml.xpath("//NessusClientData//Report//ReportName").text
    end

    def start_time
      @xml.xpath("//NessusClientData//Report//StartTime").text
    end

    def stop_time
      @xml.xpath("//NessusClientData//Report//StopTime").text
    end

    def run_time
      # Need to fine duration from start and top times
      #DateTime.parse(stop_time)
    end

    def policy_name
      @xml.xpath("//NessusClientData//Report//policyName").text
    end

    def policy_comments
      @xml.xpath("//NessusClientData//Report//policyComments").text
    end

    def plugin_selection
      ## Not Working
      @xml.xpath("//PluginSelection").text.split(';')
    end

    def hosts
      hosts = []
      @xml.xpath("//ReportHost").each do |host|
        hosts << host.at('HostName').text if host.at('HostName').text
        yield host if block_given?
      end
      hosts
    end

    def hostname
      self.at('HostName').text
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
      @xml.xpath("//ReportItem//port").text
    end

    def high_severity
      @xml.xpath("//ReportItem//severity").text
    end

    private


    def parse_host()
      host_data = {}
      @xml.xpath("//ReportHost//HostName").each do |host|
        host_data[:start_time] = host.xpath("//ReportHost//startTime").text
        host_data[:stop_time] = host.xpath("//ReportHost//startTime").text
      end
      return host_data
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
