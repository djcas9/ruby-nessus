require 'ruby-nessus/Version1/port'

module RubyNessus
  module Version1
    class Event
      # Return the total event count for a given host.
      # @return [Integer]
      #   Return the total event count for a given host.
      # @example
      #   host.event_count #=> 3456
      def initialize(event)
        @event = event
      end

      # Return the event port.
      # @return [Object]
      #    Return the event port object or port string.
      # @example
      #   event.port            #=> "https (443/tcp)"
      #   event.port.number     #=> 443
      #   event.port.service    #=> "https"
      #   event.port.protocol   #=> "tcp"
      def port
        @port ||= Port.parse(@event.at('port').inner_text)
      end

      # Return the event severity.
      # @return [String]
      #    Return the event severity.
      # @example
      #   event.severity          #=> 3
      #   event.severity.in_words #=> "High Severity"
      # @see String#in_words
      def severity
        @severity ||= @event.at('severity').inner_text.to_i
      end

      # Return the event object nessus plugin id
      # @return [String]
      #    Return the event object nessus plugin id
      # @example
      #   event.plugin_id #=> 3245
      def plugin_id
        @plugin_id ||= @event.at('pluginID').inner_text.to_i
      end

      # Return the event name (plugin_name)
      # @return [String]
      #    Return the event name (plugin_name)
      # @example
      #   event.plugin_name   #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #   event.name          #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      def plugin_name
        s = @event.at('pluginName').inner_text

        @plugin_name ||= unless s.empty?
                           @event.at('pluginName').inner_text || 'N/A'
                         else
                           false
                         end

        return @plugin_name
      end
      alias name plugin_name

      # Return the event plugin output data
      # @return [String]
      #    Return the event plugin output data
      # @example
      #   event.output        #=> "..."
      #   event.data          #=> "..."
      def data
        d = "#{@event.at('data')}" || ''

        @data ||= unless d.empty?
                    @event.at('data').inner_text || 'N/A'
                  else
                    false
                  end
        return @data
      end
      alias output data
    end
  end
end
