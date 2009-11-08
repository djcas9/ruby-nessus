module Nessus
  class Port
    # Port Service
    attr_reader :service
    # Port number
    attr_reader :number
    # Port Protocol
    attr_reader :protocol

    # Creates A New Port Object
    # @param [String] service The Port Service.
    # @param [Integer] number The Port number.
    # @param [String] protocol The Port protocol.
    # @example
    # Port.new("ssh",22,"tcp")
    def initialize(service,number,protocol)
      @service = service
      @number = (number || 0)
      @protocol = protocol
    end

    # Parse A passed port string and return a Port Object.
    # @return [Object]
    #   New Port Object
    # @example
    #   Port.parse(port)
    def Port.parse(str)
      begin
        components = str.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
        

        return Port.new(
        components[1].strip,
        components[2].strip,
        components[3].strip
        )

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
      "#{@service} (#{@number}/#{@protocol})"
    end

  end
end
