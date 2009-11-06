require 'ruby-nessus/port'

module Nessus
  class Event
    attr_reader :event

    def initialize(event)
      @event = event
    end

    def port
      @port ||= Port.parse(@event.at('port').inner_text)
    end

    def severity
      @severity ||= @event.at('severity').inner_text.to_i
    end

    def plugin_id
      @plugin_id ||= @event.at('pluginID').inner_text.to_i
    end

    def plugin_name
      s = @event.at('pluginName').inner_text
      
      @plugin_name ||= unless s.empty?
                         @event.at('pluginName').inner_text || "N/A"
                       else
                         false
                       end

      return @plugin_name
    end
    alias name plugin_name

    def data
      @data ||= @event.at('data').inner_text
    end
    alias output data

  end
end
