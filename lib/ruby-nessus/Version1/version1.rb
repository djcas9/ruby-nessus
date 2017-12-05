require 'ruby-nessus/Version1/host'
require 'ruby-nessus/Version1/event'

module RubyNessus
  # .Nessus Version 2 Schema
  module Version1
    # File to parse
    attr_reader :file

    class XML
      include Enumerable

      #
      # Creates a new .Nessus (XML) object to be parser
      #
      # @param [String] file The Nessus xml results file to parse.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created XML object.
      #
      # @yieldparam [XML] prog The newly created XML object.
      #
      # @example
      #   RubyNessus::XML.new(nessus_scan_file) do |scan|
      #     scan.report_name
      #   end
      #
      def initialize(xml)
        @xml = xml
        raise "Error: Not A Version 1.0 .Nessus file." unless @xml.at('NessusClientData')
      end

      def version
        1
      end

      #
      # Return the nessus report title.
      #
      # @return [String]
      #   The Nessus Report Title
      #
      # @example
      #   scan.report_name #=> "My Super Cool Nessus Report"
      #
      def title
        @report_name ||= @xml.xpath("//NessusClientData//Report//ReportName").inner_text.split(' - ').last
      end

      #
      # Return the nessus report time.
      #
      # @return [String]
      #   The Nessus Report Time
      #
      # @example
      #   scan.report_time #=> "09/11/08 02:21:22 AM"
      #
      def time
        datetime = @xml.xpath("//NessusClientData//Report//ReportName").inner_text.split(' - ').first
        @report_time ||= DateTime.strptime(datetime, fmt='%y/%m/%d %I:%M:%S %p')
      end

      #
      # Return the scan start time.
      #
      # @return [DateTime]
      #   The Nessus Scan Start Time
      #
      # @example
      #   scan.start_time #=> 'Fri Nov 11 23:36:54 1985'
      #
      def start_time
        @start_time = DateTime.strptime(@xml.xpath("//NessusClientData//Report//StartTime").inner_text, fmt='%a %b %d %H:%M:%S %Y')
      end

      #
      # Return the scan stop time.
      #
      # @return [DateTime]
      #   The Nessus Scan Stop Time
      #
      # @example
      #   scan.stop_time #=> 'Mon Nov 11 23:36:54 1985'
      #
      def stop_time
        @stop_time = DateTime.strptime(@xml.xpath("//NessusClientData//Report//StopTime").inner_text, fmt='%a %b %d %H:%M:%S %Y')
      end

      #
      # Return the scan run time.
      #
      # @return [String]
      #   The Nessus Scan Run Time
      #
      # @example
      #   scan.runtime #=> '2 hours 5 minutes and 16 seconds'
      #
      def runtime
        h = ("#{Time.parse(stop_time.to_s).strftime('%H').to_i - Time.parse(start_time.to_s).strftime('%H').to_i}").gsub('-', '')
        m = ("#{Time.parse(stop_time.to_s).strftime('%M').to_i - Time.parse(start_time.to_s).strftime('%M').to_i}").gsub('-', '')
        s = ("#{Time.parse(stop_time.to_s).strftime('%S').to_i - Time.parse(start_time.to_s).strftime('%S').to_i}").gsub('-', '')
        return "#{h} hours #{m} minutes and #{s} seconds"
      end

      #
      # Return the nessus scan policy name. When creating a nessus policy this is usually the title field.
      #
      # @return [String]
      #   The Nessus Scan Policy Name
      #
      def policy_title
        @policy_name ||= @xml.xpath("//NessusClientData//Report//policyName").inner_text
      end

      #
      # Return the nessus scan policy comments. This is the description field when creating a new policy with the Nessus GUI client.
      #
      # @return [String]
      #   The Nessus Scan Policy Comments
      #
      def policy_notes
        @policy_comments ||= @xml.xpath("//NessusClientData//Report//policyComments").inner_text
      end

      #
      # Return the hosts the were targeted for the initial scan.
      # These are the hosts that were inputed when creating the scan.
      #
      # @return [Array<String>]
      #   Array of hosts
      #
      def target_hosts
        hosts = []
        @xml.xpath('//Targets/Target/value').each do |element|
          hosts << element.inner_text
        end
        hosts.sort.uniq!
      end

      #
      # Returns and array of the plugin ids userd for the passed .nessus scan.
      #
      # @return [Array]
      #   The Nessus Scan Plugin Ids
      #
      # @example
      #   scan.plugin_ids #=> [1234,2343,9742,5452,5343,2423,1233]
      #
      def plugin_ids
        unless @plugin_ids
          @plugin_ids = []

          @xml.xpath("//PluginSelection").last.text.split(';').each do |id|
            @plugin_ids << id
          end
        end

        @plugin_ids
      end

      #
      # Returns and array of the plugin names userd for the passed .nessus scan.
      #
      # @return [Array]
      #   The Nessus Scan Plugin Names
      #
      # @example
      #   scan.plugins #=> ["PHP < 5.2.1 Multiple Vulnerabilities", "PHP < 4.4.1 / 5.0.6 Multiple Vulnerabilities"]
      #
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

      #
      # Creates a new Host object to be parser
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Host object.
      #
      # @yieldparam [XML] prog The newly created Host object.
      #
      # @example
      #   scan.hosts do |host|
      #     puts host.hostname
      #   end
      #
      def each_host(&block)
        hosts = []
        @xml.xpath("//ReportHost").each do |host|
          hosts << host.at('HostName').inner_text if host.at('HostName').inner_text
          block.call(Host.new(host)) if block
        end
        hosts
      end

      #
      # Parses the hosts of the scan.
      #
      # @return [Array<String>]
      #   The Hosts of the scan.
      #
      def hosts
        self.to_enum(:each_host).to_a
      end

      #
      # Return the nessus scan host count.
      #
      # @return [Integer]
      #   The Nessus Scan Host Count
      #
      # @example
      #   scan.host_count #=> 23
      #
      def host_count
        hosts.size
      end

      #
      # Retunrs an array of all unique ports.
      #
      # @return [Array]
      #
      # @example
      #   scan.unique_ports #=> 234
      #
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

      #
      # Return the informational severity count.
      #
      # @return [Integer]
      #   The Informational Severity Count
      #
      # @example
      #   scan.informational_severity_count #=> 1203
      #
      def open_ports_count
        count_severity[:open_ports].to_i
      end

      #
      # Return the High severity count.
      #
      # @return [Integer]
      #   The High Severity Count
      #
      # @example
      #   scan.high_severity_count #=> 10
      #
      def high_severity_count
        count_severity[:high].to_i
      end

      #
      # Return the Medium severity count.
      #
      # @return [Integer]
      #   The Medium Severity Count
      #
      # @example
      #   scan.medium_severity_count #=> 234
      #
      def medium_severity_count
        count_severity[:medium].to_i
      end

      #
      # Return the Low severity count.
      #
      # @return [Integer]
      #   The Low Severity Count
      #
      # @example
      #   scan.low_severity_count #=> 114
      #
      def low_severity_count
        count_severity[:low].to_i
      end

      #
      # Return the Total severity count. [high, medium, low, informational]
      #
      # @return [Integer]
      #   The Total Severity Count
      #
      # @example
      #   scan.total_event_count #=> 1561
      #
      def total_event_count
        count_severity[:all].to_i
      end

      #
      # Return the Total severity count.
      #
      # @param [String] severity the severity in which to calculate percentage for.
      #
      # @param [Boolean] round round the result to the nearest whole number.
      #
      # @raise [ExceptionClass] One of the following severity options must be passed. [high, medium, low, informational, all]
      #
      # @return [Integer]
      #   The Percentage Of Events For A Passed Severity
      #
      # @example
      #   scan.event_percentage_for("low", true) #=> 11%
      #
      def event_percentage_for(type, round_percentage=false)
        @sc ||= count_severity
        if %W(high medium low all).include?(type)
          calc = ((@sc[:"#{type}"].to_f / @sc[:all].to_f) * 100)
          if round_percentage
            return "#{calc.round}"
          else
            return "#{calc}"
          end
        else
          raise "Error: #{type} is not an acceptable severity. Possible options include: all, high, medium, low and informational."
        end
      end

      #
      # Creates a new Host object to be parser from a passed search param.
      #
      # @param [String] hostname the hostname to build a Host object for.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Host object.
      #
      # @yieldparam [XML] prog The newly created Host object.
      #
      # @example
      #   scan.find_by_hostname('127.0.0.1') do |host|
      #     puts host.hostname
      #   end
      #
      def find_by_hostname(hostname, &block)
        raise "Error: hostname can't be blank." if hostname.blank?
        @xml.xpath('//ReportHost[HostName]').each do |host|
          next unless host.inner_text.match(hostname)
          block.call(Host.new(host)) if block
        end
      end

      private

        #
        # Calculates an event hash of totals for severity counts.
        #
        # @return [hash]
        #   The Event Totals For Severity
        #
        def count_severity
          unless @count
            @count = {}
            @open_ports = 0
            @low = 0
            @medium = 0
            @high = 0

            @xml.xpath("//ReportHost").each do |s|
              @open_ports += s.at('num_ports').inner_text.to_i
              @low += s.at('num_lo').inner_text.to_i
              @medium += s.at('num_med').inner_text.to_i
              @high += s.at('num_hi').inner_text.to_i
            end

            @count = { :open_ports => @open_ports,
                       :low => @low,
                       :medium => @medium,
                       :high => @high,
                       :all => (@low + @medium + @high) }
          end

          return @count
        end
    end
  end
end
