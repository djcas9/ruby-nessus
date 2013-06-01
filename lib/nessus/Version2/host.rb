module Nessus
  module Version2

    class Host
      include Enumerable

      #
      # Creates A New Host Object
      #
      # @param [Object] Host Object
      #
      # @example
      # Host.new(object)
      #
      def initialize(host)
        @host = host
      end

      def to_s
        "#{ip}"
      end

      #
      # Return the Host Object hostname.
      #
      # @return [String]
      #   The Host Object Hostname
      #
      # @example
      #   host.hostname #=> "example.com"
      #
      def hostname
        if (host = @host.at('tag[name=host-fqdn]'))
          host.inner_text
        end
      end
      alias name hostname
      alias fqdn hostname
      alias dns_name hostname

      #
      # Return the Host Object IP.
      #
      # @return [String]
      #   The Host Object IP
      #
      # @example
      #   host.ip #=> "127.0.0.1"
      #
      def ip
        if (ip = @host.at('tag[name=host-ip]'))
          ip.inner_text
        end
      end

      #
      # Return the host scan start time.
      #
      # @return [DateTime]
      #   The Host Scan Start Time
      #
      # @example
      #   scan.scan_start_time #=> 'Fri Nov 11 23:36:54 1985'
      #
      def start_time
        if (start_time = @host.at('tag[name=HOST_START]'))
          DateTime.strptime(start_time.inner_text, fmt='%a %b %d %H:%M:%S %Y')
        else
          false
        end
      end

      #
      # Return the host scan stop time.
      #
      # @return [DateTime]
      #   The Host Scan Stop Time
      #
      # @example
      #   scan.scan_start_time #=> 'Fri Nov 11 23:36:54 1985'
      #
      def stop_time
        if (stop_time = @host.at('tag[name=HOST_END]'))
          DateTime.strptime(stop_time.inner_text, fmt='%a %b %d %H:%M:%S %Y')
        else
          false
        end
      end

      #
      # Return the host run time.
      #
      # @return [String]
      #   The Host Scan Run Time
      #
      # @example
      #   scan.scan_run_time #=> '2 hours 5 minutes and 16 seconds'
      #
      def runtime
        get_runtime
      end
      alias scan_runtime runtime

      #
      # Return the Host Netbios Name.
      #
      # @return [String]
      #   The Host Netbios Name
      #
      # @example
      #   host.netbios_name #=> "SOMENAME4243"
      #
      def netbios_name
        if (netbios = @host.at('tag[name=netbios-name]'))
          netbios.inner_text
        end
      end

      #
      # Return the Host Mac Address.
      #
      # @return [String]
      #   Return the Host Mac Address
      #
      # @example
      #   host.mac_addr #=> "00:11:22:33:44:55"
      #
      def mac_addr
        if (mac_addr = @host.at('tag[name=mac-addr]'))
          mac_addr.inner_text
        end
      end
      alias mac_address mac_addr

      #
      # Return the Host OS Name.
      #
      # @return [String]
      #   Return the Host OS Name
      #
      # @example
      #   host.dns_name #=> "Microsoft Windows 2000, Microsoft Windows Server 2003"
      #
      def os_name
        if (os_name = @host.at('tag[name=operating-system]'))
          os_name.inner_text
        end
      end
      alias os os_name
      alias operating_system os_name

      #
      # Return the open ports for a given host object.
      #
      # @return [Integer]
      #   Return the open ports for a given host object.
      #
      # @example
      #   host.open_ports #=> 213
      #
      def open_ports
        @scanned_ports ||= host_stats[:open_ports].to_i
      end

      #
      # Returns All Informational Event Objects For A Given Host.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      #
      # @yieldparam [EVENT] prog The newly created Event object.
      #
      # @return [Integer]
      #   Return The Informational Event Count For A Given Host.
      #
      # @example
      #   host.informational_severity_events do |info|
      #     puts info.port
      #     puts info.data if info.data
      #   end
      #
      def informational_severity_events(&block)
        unless @informational_events
          @informational_events = []

          @host.xpath("ReportItem").each do |event|
            next if event['severity'].to_i != 0
            @informational_events << Event.new(event)
          end

        end

        @informational_events.each(&block)
      end

      #
      # Returns All Low Event Objects For A Given Host.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      #
      # @yieldparam [EVENT] prog The newly created Event object.
      #
      # @return [Integer]
      #   Return The Low Event Count For A Given Host.
      #
      # @example
      #   host.low_severity_events do |low|
      #     puts low.name if low.name
      #   end
      #
      def low_severity_events(&block)

        unless @low_severity_events
          @low_severity_events = []

          @host.xpath("ReportItem").each do |event|
            next if event['severity'].to_i != 1
            @low_severity_events << Event.new(event)
          end

        end

        @low_severity_events.each(&block)
      end

      #
      # Returns All Medium Event Objects For A Given Host.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      #
      # @return [Integer]
      #   Return The Medium Event Count For A Given Host.
      #
      # @example
      #   host.medium_severity_events do |medium|
      #     puts medium.name if medium.name
      #   end
      #
      def medium_severity_events(&block)

        unless @medium_severity_events
          @medium_severity_events = []

          @host.xpath("ReportItem").each do |event|
            next if event['severity'].to_i != 2
            @medium_severity_events << Event.new(event)
          end

        end

        @medium_severity_events.each(&block)
      end

      def medium_severity
        Enumerator.new(self,:medium_severity_events).to_a
      end

      #
      # Returns All High Event Objects For A Given Host.
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      #
      # @yieldparam [EVENT] prog The newly created Event object.
      #
      # @return [Integer]
      #   Return The High Event Count For A Given Host.
      #
      # @example
      #   host.high_severity_events do |high|
      #     puts high.name if high.name
      #   end
      #
      def high_severity_events(&block)

        unless @high_severity_events
          @high_severity_events = []

          @host.xpath("ReportItem").each do |event|
            next if event['severity'].to_i != 3
            @high_severity_events << Event.new(event)
          end

        end

        @high_severity_events.each(&block)
      end

      #
      # Return the total event count for a given host.
      #
      # @return [Integer]
      #   Return the total event count for a given host.
      #
      # @example
      #   host.event_count #=> 3456
      #
      def event_count
        ((low_severity_events.count) + (medium_severity_events.count) + (high_severity_events.count)).to_i
      end

      #
      # Creates a new Event object to be parser
      #
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      #
      # @example
      #   host.each_event do |event|
      #     puts event.name if event.name
      #     puts event.port
      #   end
      #
      def each_event(&block)
        @host.xpath("ReportItem").each do |event|
          block.call(Event.new(event)) if block
        end
      end

      #
      # Parses the events of the host.
      #
      # @return [Array<String>]
      #   The events of the host.
      #
      def events
        Enumerator.new(self,:each_event).to_a
      end

      #
      # Return an Array of open ports. 
      #
      # @return [Array]
      #   The open ports
      #
      # @example
      #   scan.ports #=> ['22', '80', '443']
      #
      def ports
        unless @ports
          @ports = []
          @host.xpath("ReportItem").each do |port|
            @ports << port['port']
          end
          @ports.uniq!
          @ports.sort!
        end
        @ports
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
        host_stats[:tcp].to_i
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
        host_stats[:udp].to_i
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
        host_stats[:icmp].to_i
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
        host_stats[:informational].to_i
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
        host_stats[:high].to_i
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
        host_stats[:medium].to_i
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
        host_stats[:low].to_i
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
      def total_event_count(count_informational = false)
        if count_informational
          host_stats[:all].to_i + informational_severity_count
        else
          host_stats[:all].to_i
        end
      end

      #
      # Return the Total severity count.
      #
      # @param [String] severity the severity in which to calculate percentage for.
      #
      # @param [true, false] round round the result to the nearest whole number.
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
        @sc ||= host_stats
        if %W(high medium low tcp udp icmp all).include?(type)
          calc = ((@sc[:"#{type}"].to_f / (@sc[:all].to_f)) * 100)
          if round_percentage
            return "#{calc.round}"
          else
            return "#{calc}"
          end
        else
          raise "Error: #{type} is not an acceptable severity. Possible options include: all, tdp, udp, icmp, high, medium and low."
        end
      end

      private

        def get_runtime
          if stop_time && start_time
            h = ("#{Time.parse(stop_time.to_s).strftime('%H').to_i - Time.parse(start_time.to_s).strftime('%H').to_i}").gsub('-', '')
            m = ("#{Time.parse(stop_time.to_s).strftime('%M').to_i - Time.parse(start_time.to_s).strftime('%M').to_i}").gsub('-', '')
            s = ("#{Time.parse(stop_time.to_s).strftime('%S').to_i - Time.parse(start_time.to_s).strftime('%S').to_i}").gsub('-', '')
            return "#{h} hours #{m} minutes and #{s} seconds"
          else
            false
          end
        end

        def host_stats

          unless @host_stats
            @host_stats = {}
            @open_ports, @tcp, @udp, @icmp, @informational, @low, @medium, @high = 0,0,0,0,0,0,0,0

            @host.xpath("ReportItem").each do |s|
              case s['severity'].to_i
                when 0
                  @informational += 1
                when 1
                  @low += 1
                when 2
                  @medium += 1
                when 3
                  @high += 1
              end

              unless s['severity'].to_i == 0
                @tcp += 1 if s['protocol'] == 'tcp'
                @udp += 1 if s['protocol'] == 'udp'
                @icmp += 1 if s['protocol'] == 'icmp'
              end

              @open_ports += 1 if s['port'].to_i != 0
            end

            @host_stats = {:open_ports => @open_ports,
                           :tcp => @tcp,
                           :udp => @udp,
                           :icmp => @icmp,
                           :informational => @informational,
                           :low => @low,
                           :medium => @medium,
                           :high => @high,
                           :all => (@low + @medium + @high)}

          end
          @host_stats
        end

    end
  end
end
