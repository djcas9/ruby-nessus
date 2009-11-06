module Nessus
  class Event
    attr_reader :event

    def initialize(event)
      @event = event
    end

    def port
      # Example: "ncube-lm (1521/tcp)"
      @port = @event.at('port').inner_text

      @port.instance_eval do
        @p = self.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
        def port_type
          if @p
            @p[1].strip unless @p[1].strip.nil?
          else
            false
          end
        end
        def port_service
          if @p
            @p[2].strip unless @p[2].strip.nil?
          else
            false
          end
        end
        def port_proto
          if @p
            @p[3].strip unless @p[3].nil?
          else
            false
          end
        end

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
