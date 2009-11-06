require 'ruby-nessus/port'

module Nessus
  class Event
    attr_reader :event

    def initialize(event)
      @event = event
    end

    def port
      unless @port
        # Example: "ncube-lm (1521/tcp)"
        port_text = @event.at('port').inner_text
        port_components = port_text.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)

        @port = Port.new(
          port_components[0].strip,
          port_components[1].strip.to_i,
          port_components[2].strip
        )
      end

      return @port
    end

    def severity
      @severity = @event.at('severity').inner_text.to_i
      return @severity
    end

    def plugin_id
      @event.at('pluginID').inner_text.to_i
    end

    def plugin_name
      i = @event.at('pluginName').inner_text
      unless (i == "")
        return @event.at('pluginName').inner_text || "N/A"
      end
      false
    end
    alias name plugin_name

    def data
      @event.at('data').inner_text
    end
    alias output data

  end
end
