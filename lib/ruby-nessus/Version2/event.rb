require 'ruby-nessus/Version2/port'

module Nessus
  module Version2

    class Event
      # Event
      attr_reader :event

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
        @port ||= Port.new(@event.at('@port'), @event.at('@svc_name'), @event.at('@protocol'))
      end

      # Return the event severity.
      # @return [String]
      #    Return the event severity.
      # @example
      #   event.severity          #=> 3
      #   event.severity.in_words #=> "High Severity"
      # @see String#in_words
      def severity
        @severity ||= @event.at('@severity').inner_text.to_i
      end

      def informational?
        severity == 0
      end

      def low?
        severity == 1
      end

      def medium?
        severity == 2
      end

      def high?
        severity == 3
      end

      # Return the event object nessus plugin id
      # @return [String]
      #    Return the event object nessus plugin id
      # @example
      #   event.plugin_id #=> 3245
      def id
        @plugin_id ||= @event.at('@pluginID').inner_text.to_i
      end
      alias plugin_id id

      def family
        @plugin_family ||= @event.at('@pluginFamily').inner_text
      end
      alias plugin_family family

      # Return the event name (plugin_name)
      # @return [String]
      #    Return the event name (plugin_name)
      # @example
      #   event.plugin_name   #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #   event.name          #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      def plugin_name
        s = @event.at('@pluginName').inner_text

        @plugin_name ||= if s.empty?
          false
        else
          @event.at('@pluginName').inner_text
        end

        return @plugin_name
      end
      alias name plugin_name


      def synopsis
        @synopsis ||= if @event.at('synopsis')
          @event.at('synopsis').inner_text
        else
          false
        end
      end

      def description
        @synopsis ||= if @event.at('description')
          @event.at('description').inner_text
        else
          false
        end
      end

      def solution
        @solution ||= if @event.at('solution')
          @event.at('solution').inner_text
        else
          false
        end
      end

      def risk
        @risk_factor ||= if @event.at('risk_factor')
          @event.at('risk_factor').inner_text
        else
          false
        end
      end

      def output
        @plugin_output ||= if @event.at('plugin_output')
          @event.at('plugin_output').inner_text
        else
          false
        end
      end
      alias data output
      alias plugin_output output

      def version
        @plugin_version ||= if @event.at('plugin_version')
          @event.at('plugin_version').inner_text
        else
          false
        end
      end
      alias plugin_version version

      def see_also
        unless @see_also
          @see_also = []
          @event.xpath("see_also").each do |see_also|
            @see_also << see_also.inner_text
          end
        end
        @see_also
      end

      def patch_publication_date
        @patch_publication_date ||= if @event.at('patch_publication_date')
          DateTime.strptime(@event.at('patch_publication_date').inner_text, fmt='%Y/%m/%d')
        else
          false
        end
      end

      def cvss_base_score
        @cvss_base_score ||= if @event.at('cvss_base_score')
          @event.at('cvss_base_score').inner_text.to_f
        else
          false
        end
      end
      
      def cve
        @cve ||= if @event.at('cve')
          @event.at('cve').inner_text
        else
          false
        end
      end

      def bid
        @bid ||= if @event.at('bid')
          @event.at('bid').inner_text.to_i
        else
          false
        end
      end

      def xref
        unless @xref
          @xref = []
          @event.xpath("xref").each do |xref|
            @xref << xref.inner_text
          end
        end
        @xref
      end

      def cvss_vector
        @cvss_vector ||= if @event.at('cvss_vector')
          @event.at('cvss_vector').inner_text
        else
          false
        end
      end

    end

  end

end
