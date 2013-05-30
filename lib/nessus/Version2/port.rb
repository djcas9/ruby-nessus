module Nessus
  module Version2
    
    class Port

      # Port Service
      attr_reader :service
      # Port number
      attr_reader :number
      # Port Protocol
      attr_reader :protocol
      
      #
      # Creates A New Port Object
      #
      # @param [String] number The port number.
      #
      # @param [String] service The port service.
      #
      # @param [String] protocol The port protocol.
      #
      # @example
      # Port.new(number, service, )
      #
      def initialize(number, service, protocol)
        @number = number
        @service = service
        @protocol = protocol
      end

      #
      # Return true if the port protocol is tcp.
      #
      # @return [Boolean]
      #   Return True If The Port Protocol Is TCP.
      #
      def tcp?
        @protocol.to_s == 'tcp'
      end

      #
      # Return true if the port protocol is udp.
      #
      # @return [Boolean]
      #   Return True If The Port Protocol Is UDP.
      #
      def udp?
        @protocol.to_s == 'udp'
      end
      
      #
      # Return true if the port protocol is icmp.
      #
      # @return [Boolean]
      #   Return True If The Port Protocol Is ICMP.
      #
      def icmp?
        @protocol.to_s == 'icmp'
      end

      #
      # Return the port as a string.
      #
      # @return [String]
      #   Return The Port As A String
      #
      # @example
      #   port.to_s #=> https (443/tcp)
      #
      def to_s
        "#{@service} (#{@number}/#{@protocol})"
      end


    end
    
  end

end
