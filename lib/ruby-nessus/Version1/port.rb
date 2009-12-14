module Nessus
  module Version1
    
    class Port

      # Port Service
      attr_reader :service
      # Port number
      attr_reader :number
      # Port Protocol
      attr_reader :protocol
      # Raw output string from nessus
      attr_reader :raw_string

      # Creates A New Port Object
      # @param [String] service The Port Service.
      # @param [Integer] number The Port number.
      # @param [String] protocol The Port protocol.
      # @param [String] raw output string from nessus.
      # @example
      # Port.new("ssh",22,"tcp", str)
      def initialize(service,number,protocol,raw_string)
        @service = service
        @number = number
        @protocol = protocol
        @raw_string = raw_string
      end

      # Parse A passed port string and return a Port Object.
      # @return [Object]
      #   New Port Object
      # @example
      #   Port.parse(port)
      def Port.parse(str)
        begin
          @full_port = str
          components = str.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)

          if components
            return Port.new(components[1].strip, components[2].strip, components[3].strip, str)
          else
            return Port.new(false, false, false, str)
          end

        end

      end

      # Return true iF port protocol Ii tcp.
      # @return [Boolean]
      #   Return True If The Port Protocol Is TCP.
      def tcp?
        @protocol == 'tcp'
      end

      # Return true iF port protocol Ii udp.
      # @return [Boolean]
      #   Return True If The Port Protocol Is UDP.
      def udp?
        @protocol == 'udp'
      end

      # Return the port as a string.
      # @return [String]
      #   Return The Port As A String
      # @example
      #   port.to_s #=> https (443/tcp)
      def to_s
        if @service && @number && @protocol
          "#{@service} (#{@number}/#{@protocol})"
        else
          "#{@raw_string}"
        end
      end

      # Return false if the port object number is nil
      # @return [Boolean]
      #   Return false if the port object number is nil
      def number
        if @number
          return @number
        else
          false
        end
      end

    end
    
  end

end
