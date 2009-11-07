module Nessus
  class Port

    attr_reader :service

    attr_reader :number

    attr_reader :protocol

    def initialize(service,number,protocol)
      @service = service
      @number = number
      @protocol = protocol
    end

    def Port.parse(str)
      # Example: "ncube-lm (1521/tcp)"
      components = str.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)

      return Port.new(
        components[0].strip,
        components[1].strip.to_i,
        components[2].strip
      )
    end

    def tcp?
      @protocol == 'tcp'
    end

    def udp?
      @protocol == 'udp'
    end

    def to_s
      "#{@service} (#{@number}/#{@protocol})"
    end

  end
end
