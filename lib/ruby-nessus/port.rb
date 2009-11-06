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
