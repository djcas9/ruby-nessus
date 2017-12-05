module RubyNessus
  module Version1
    class Host
      include Enumerable

      # Creates A New Host Object
      # @param [Object] Host Object
      # @example
      # Host.new(object)
      def initialize(host)
        @host = host
      end

      def to_s
        ip.to_s
      end

      # Return the Host Object hostname.
      # @return [String]
      #   The Host Object Hostname
      # @example
      #   host.hostname #=> "127.0.0.1"
      def hostname
        @hostname ||= @host.at('HostName').inner_text
      end
      alias ip hostname

      # Return the host scan start time.
      # @return [DateTime]
      #   The Host Scan Start Time
      # @example
      #   scan.scan_start_time #=> 'Fri Nov 11 23:36:54 1985'
      def scan_start_time
        if @host.at('startTime').inner_text.blank?
          false
        else
          @host_scan_time = DateTime.strptime(@host.at('startTime').inner_text, '%a %b %d %H:%M:%S %Y')
        end
      end

      # Return the host scan stop time.
      # @return [DateTime]
      #   The Host Scan Stop Time
      # @example
      #   scan.scan_start_time #=> 'Fri Nov 11 23:36:54 1985'
      def scan_stop_time
        if @host.at('stopTime').inner_text.blank?
          false
        else
          @host_scan_time = DateTime.strptime(@host.at('stopTime').inner_text, '%a %b %d %H:%M:%S %Y')
        end
      end

      # Return the host run time.
      # @return [String]
      #   The Host Scan Run Time
      # @example
      #   scan.scan_run_time #=> '2 hours 5 minutes and 16 seconds'
      def scan_runtime
        get_runtime
      end
      alias runtime scan_runtime

      # Return the Host Netbios Name.
      # @return [String]
      #   The Host Netbios Name
      # @example
      #   host.netbios_name #=> "SOMENAME4243"
      def netbios_name
        @netbios_name ||= @host.at('netbios_name').inner_text
      end

      # Return the Host Mac Address.
      # @return [String]
      #   Return the Host Mac Address
      # @example
      #   host.mac_addr #=> "00:11:22:33:44:55"
      def mac_addr
        @mac_addr ||= @host.at('mac_addr').inner_text
      end
      alias mac_address mac_addr

      # Return the Host DNS Name.
      # @return [String]
      #   Return the Host DNS Name
      # @example
      #   host.dns_name #=> "snorby.org"
      def dns_name
        @dns_name ||= @host.at('dns_name').inner_text
      end

      # Return the Host OS Name.
      # @return [String]
      #   Return the Host OS Name
      # @example
      #   host.dns_name #=> "Microsoft Windows 2000, Microsoft Windows Server 2003"
      def os_name
        @os_name ||= @host.at('os_name').inner_text
      end
      alias operating_system os_name

      # Return the open ports for a given host object.
      # @return [Integer]
      #   Return the open ports for a given host object.
      # @example
      #   host.open_ports #=> 213
      def open_ports
        @scanned_ports ||= @host.at('num_ports').inner_text.to_i
      end

      # Returns All Informational Event Objects For A Given Host.
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      # @return [Integer]
      #   Return The Informational Event Count For A Given Host.
      # @example
      #   host.informational_events do |info|
      #     puts info.port
      #     puts info.data if info.data
      #   end
      def informational_events(&block)
        unless @informational_events
          @informational_events = []
          @informational_event_count = 0

          @host.xpath('ReportItem').each do |event|
            next if event.at('severity').inner_text.to_i != 0
            @informational_events << Event.new(event)
            @informational_event_count += 1
          end

        end

        @informational_events.each(&block)
        @informational_event_count
      end

      # Returns All Low Event Objects For A Given Host.
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      # @return [Integer]
      #   Return The Low Event Count For A Given Host.
      # @example
      #   host.low_severity_events do |low|
      #     puts low.name if low.name
      #   end
      def low_severity_events(&block)
        @low_severity_count = @host.at('num_lo').inner_text.to_i

        unless @low_severity_events
          @low_severity_events = []

          @host.xpath('ReportItem').each do |event|
            next if event.at('severity').inner_text.to_i != 1
            @low_severity_events << Event.new(event)
          end

        end

        @low_severity_events.each(&block)
        @low_severity_count
      end

      # Returns All Medium Event Objects For A Given Host.
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      # @return [Integer]
      #   Return The Medium Event Count For A Given Host.
      # @example
      #   host.medium_severity_events do |medium|
      #     puts medium.name if medium.name
      #   end
      def medium_severity_events(&block)
        @high_severity_count = @host.at('num_med').inner_text.to_i

        unless @medium_severity_events
          @medium_severity_events = []

          @host.xpath('ReportItem').each do |event|
            next if event.at('severity').inner_text.to_i != 2
            @medium_severity_events << Event.new(event)
          end

        end

        @medium_severity_events.each(&block)
        @high_severity_count
      end

      # Returns All High Event Objects For A Given Host.
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      # @return [Integer]
      #   Return The High Event Count For A Given Host.
      # @example
      #   host.high_severity_events do |high|
      #     puts high.name if high.name
      #   end
      def high_severity_events(&block)
        @high_severity_count = @host.at('num_hi').inner_text.to_i

        unless @high_severity_events
          @high_severity_events = []

          @host.xpath('ReportItem').each do |event|
            next if event.at('severity').inner_text.to_i != 3
            @high_severity_events << Event.new(event)
          end

        end

        @high_severity_events.each(&block)
        @high_severity_count
      end

      # Return the total event count for a given host.
      # @return [Integer]
      #   Return the total event count for a given host.
      # @example
      #   host.event_count #=> 3456
      def event_count
        (low_severity_events.to_i + medium_severity_events.to_i + high_severity_events.to_i).to_i
      end

      # Creates a new Event object to be parser
      # @yield [prog] If a block is given, it will be passed the newly
      #               created Event object.
      # @yieldparam [EVENT] prog The newly created Event object.
      # @example
      #   host.events do |event|
      #     puts event.name if event.name
      #     puts event.port
      #   end
      def each_event(&block)
        @host.xpath('ReportItem').each do |event|
          block.call(Event.new(event)) if block
        end
      end

      # Parses the events of the host.
      # @return [Array<String>]
      #   The events of the host.
      def events
        to_enum(:each_event).to_a
      end

      private

      def get_runtime
        if scan_start_time && scan_stop_time
          h = (Time.parse(scan_stop_time.to_s).strftime('%H').to_i - Time.parse(scan_start_time.to_s).strftime('%H').to_i).to_s.gsub('-', '')
          m = (Time.parse(scan_stop_time.to_s).strftime('%M').to_i - Time.parse(scan_start_time.to_s).strftime('%M').to_i).to_s.gsub('-', '')
          s = (Time.parse(scan_stop_time.to_s).strftime('%S').to_i - Time.parse(scan_start_time.to_s).strftime('%S').to_i).to_s.gsub('-', '')
          "#{h} hours #{m} minutes and #{s} seconds"
        else
          false
        end
      end
    end
  end
end
