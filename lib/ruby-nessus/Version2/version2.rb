require 'ruby-nessus/Version2/host'
require 'ruby-nessus/Version2/event'

module RubyNessus
  # .Nessus Version 2 Schema
  module Version2
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
      # @yieldparam [XML] prog The newly created XML object.
      #
      # @example
      #   RubyNessus::XML.new(nessus_scan_file) do |scan|
      #     scan.report_name
      #   end
      #
      def initialize(xml)
        @xml = xml
        raise 'Error: Not A Version 2.0 .Nessus file.' unless @xml.at('NessusClientData_v2')
      end

      def version
        2
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
        @report_name ||= @xml.at('Report/@name').inner_text
      end

      #
      # Return the nessus scan policy name. When creating a nessus policy this is usually the title field.
      #
      # @return [String]
      #   The Nessus Scan Policy Name
      #
      def policy_title
        @policy_name ||= @xml.at('//Policy/policyName').inner_text
      end

      #
      # Return the nessus scan policy comments. This is the description field when creating a new policy with the Nessus GUI client.
      #
      # @return [String]
      #   The Nessus Scan Policy Comments
      #
      def policy_notes
        @policy_notes ||= @xml.at('//Policy/policyComments').inner_text
      end

      #
      # Return the hosts the were targeted for the initial scan.
      # These are the hosts that were inputed when creating the scan.
      #
      # @return [Array<String>]
      #   Array of hosts
      #
      def target_hosts
        @xml.xpath('//Preferences/ServerPreferences/preference').each do |element|
          if element.children[0].inner_text == 'TARGET'
            return element.children[2].inner_text.split(',')
          end
        end
      end

      #
      # Creates a new Host object to be parser
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Host object.
      # @yieldparam [XML] prog The newly created Host object.
      #
      # @example
      #   scan.hosts do |host|
      #     puts host.hostname
      #   end
      #
      def each_host(&block)
        hosts = []
        @xml.xpath('//ReportHost').each do |host|
          hosts << host['name'] if host['name']
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
        each_host.size
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
          @xml.xpath('//ReportItem').each do |port|
            @unique_ports << port['port']
          end
          @unique_ports.uniq!
          @unique_ports.sort!
        end
      end

      #
      # Return the Open Ports count.
      #
      # @return [Integer]
      #   The Open Ports Count
      #
      # @example
      #   scan.open_ports_count #=> 1203
      #
      def open_ports_count
        count_stats[:open_ports].to_i
      end

      #
      # Return the TCP Event Count.
      #
      # @return [Integer]
      #   The TCP Event Count
      #
      # @example
      #   scan.tcp_count #=> 3
      #
      def tcp_count
        count_stats[:tcp].to_i
      end

      #
      # Return the UDP Event Count.
      #
      # @return [Integer]
      #   The UDP Event Count
      #
      # @example
      #   scan.udp_count #=> 3
      #
      def udp_count
        count_stats[:udp].to_i
      end

      #
      # Return the ICMP Event Count.
      #
      # @return [Integer]
      #   The ICMP Event Count
      #
      # @example
      #   scan.icmp_count #=> 3
      #
      def icmp_count
        count_stats[:icmp].to_i
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
      def informational_severity_count
        count_stats[:informational].to_i
      end

      #
      # Return the Critical severity count.
      #
      # @return [Integer]
      #   The Critical Severity Count
      #
      # @example
      #   scan.critical_severity_count #=> 10
      #
      def critical_severity_count
        count_stats[:critical].to_i
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
        count_stats[:high].to_i
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
        count_stats[:medium].to_i
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
        count_stats[:low].to_i
      end

      #
      # Return the Total severity count. [critical, high, medium, low, informational]
      #
      # @param [true, false] argname only true or false
      #
      # @return [Integer]
      #   The Total Severity Count
      #
      # @example
      #   scan.total_event_count #=> 1561
      #
      def total_event_count(count_informational = false)
        if count_informational
          count_stats[:all].to_i + informational_severity_count
        else
          count_stats[:all].to_i
        end
      end

      #
      # Return the Total severity count.
      #
      # @param [String] severity the severity in which to calculate percentage for.
      #
      # @param [Boolean] round round the result to the nearest whole number.
      #
      # @raise [ExceptionClass] One of the following severity options must be passed. [critical, high, medium, low, informational, all]
      #
      # @return [Integer]
      #   The Percentage Of Events For A Passed Severity
      #
      # @example
      #   scan.event_percentage_for("low", true) #=> 11%
      #
      def event_percentage_for(type, round_percentage = false)
        @sc ||= count_stats
        if %W(critical high medium low tcp udp icmp all).include?(type)
          calc = ((@sc[:"#{type}"].to_f / @sc[:all].to_f) * 100)
          if round_percentage
            return "#{calc.round}"
          else
            return "#{calc}"
          end
        else
          raise "Error: #{type} is not an acceptable severity. Possible options include: all, tdp, udp, icmp, critical, high, medium and low."
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
        @xml.xpath('//ReportHost').each do |host|
          next unless host['name'].match(hostname)
          block.call(Host.new(host)) if block
        end
      end

      private

      #
      # Calculates an event hash of totals for severity counts.
      #
      # @return [Hash]
      #   The Event Totals For Severity
      #
      def count_stats
        unless @count
          @count = {}
          @open_ports, @tcp, @udp, @icmp, @informational, @low, @medium, @high, @critical = 0, 0, 0, 0, 0, 0, 0, 0, 0

          @xml.xpath('//ReportItem').each do |s|
            case s['severity'].to_i
            when 0
              @informational += 1
            when 1
              @low += 1
            when 2
              @medium += 1
            when 3
              @high += 1
            when 4
              @critical += 1
            end

            unless s['severity'].to_i == 0
              @tcp += 1 if s['protocol'] == 'tcp'
              @udp += 1 if s['protocol'] == 'udp'
              @icmp += 1 if s['protocol'] == 'icmp'
            end

            @open_ports += 1 if s['port'].to_i != 0
          end

          @count = { :open_ports => @open_ports,
                     :tcp => @tcp,
                     :udp => @udp,
                     :icmp => @icmp,
                     :informational => @informational,
                     :low => @low,
                     :medium => @medium,
                     :high => @high,
                     :critical => @critical,
                     :all => (@low + @medium + @high + @critical) }
        end

        return @count
      end
    end
  end
end
