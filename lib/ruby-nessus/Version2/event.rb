require 'ruby-nessus/Version2/port'

module RubyNessus
  module Version2

    class Event

      def initialize(event)
        @event = event
      end

      #
      # Return the event port.
      #
      # @return [Object]
      #    Return the event port object or port string.
      #
      # @example
      #   event.port            #=> "https (443/tcp)"
      #   event.port.number     #=> 443
      #   event.port.service    #=> "https"
      #   event.port.protocol   #=> "tcp"
      #
      def port
        @port ||= Port.new(@event.at('@port'), @event.at('@svc_name'), @event.at('@protocol'))
      end

      #
      # Return the event severity.
      #
      # @return [String]
      #    Return the event severity.
      #
      # @example
      #   event.severity          #=> 3
      #   event.severity.in_words #=> "High Severity"
      #
      # @see String#in_words
      #
      def severity
        @severity ||= @event.at('@severity').inner_text.to_i
      end

      #
      # Return true if event is of informational severity.
      #
      # @return [Boolean]
      #    Return true if the event is informational.
      #
      def informational?
        severity == 0
      end

      #
      # Return true if the event is of low severity.
      #
      # @return [Boolean]
      #   Return true if the event is low severity.
      # 
      def low?
        severity == 1
      end

      #
      # Return true if the event is of medium severity.
      #
      # @return [Boolean]
      #   Return true if the event is medium severity.
      #
      def medium?
        severity == 2
      end

      #
      # Return true if the event is of high severity.
      #
      # @return [Boolean]
      #   Return true if the event is high severity.
      #
      def high?
        severity == 3
      end

      #
      # Return true if the event is of critical severity.
      #
      # @return [Boolean]
      #   Return true if the event is critical severity.
      #
      def critical?
        severity == 4
      end
      
      #
      # Return the event object nessus plugin id
      #
      # @return [String]
      #    Return the event object nessus plugin id
      #
      # @example
      #   event.plugin_id #=> 3245
      #
      def id
        @plugin_id ||= @event.at('@pluginID').inner_text.to_i
      end
      alias plugin_id id

      #
      # Return the event object plugin family name.
      #
      # @return [String]
      #   Return the event object plugin family name.
      #
      # @example
      #   event.family #=> "Service detection"
      #
      def family
        @plugin_family ||= @event.at('@pluginFamily').inner_text
      end
      alias plugin_family family

      #
      # Return the event name (plugin_name)
      #
      # @return [String, false]
      #    Return the event name (plugin_name)
      #
      # @example
      #   event.plugin_name   #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #   event.name          #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #
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

      #
      # Return the event synopsis.
      #
      # @return [String, false]
      #    Return the event synopsis.
      #
      def synopsis
        @synopsis ||= if @event.at('synopsis')
          @event.at('synopsis').inner_text
        else
          false
        end
      end

      #
      # Return the event description.
      #
      # @return [String, false]
      #    Return the event description.
      #
      def description
        @description ||= if @event.at('description')
          @event.at('description').inner_text
        else
          false
        end
      end

      #
      # Return the event solution.
      #
      # @return [String, false]
      #    Return the event solution.
      #
      def solution
        @solution ||= if @event.at('solution')
          @event.at('solution').inner_text
        else
          false
        end
      end

      #
      # Return the event risk.
      #
      # @return [String, false]
      #    Return the event risk.
      #
      def risk
        @risk_factor ||= if @event.at('risk_factor')
          @event.at('risk_factor').inner_text
        else
          false
        end
      end

      #
      # Return the event plugin output.
      #
      # @return [String, false]
      #    Return the event plugin output.
      #
      def output
        @plugin_output ||= if @event.at('plugin_output')
          @event.at('plugin_output').inner_text
        else
          false
        end
      end
      alias data output
      alias plugin_output output

      #
      # Return the event plugin version.
      #
      # @return [String, false]
      #    Return the event plugin version.
      #
      def version
        @plugin_version ||= if @event.at('plugin_version')
          @event.at('plugin_version').inner_text
        else
          false
        end
      end
      alias plugin_version version

      #
      # Return the event reference links.
      #
      # @return [String, false]
      #    Return the event reference links.
      #
      def see_also
        unless @see_also
          @see_also = []
          @event.xpath("see_also").each do |see_also|
            @see_also << see_also.inner_text
          end
        end
        @see_also
      end
      alias links see_also
      alias more see_also
      alias references see_also

      #
      # Return the event patch publication date.
      #
      # @return [String, false]
      #    Return the event patch publication date.
      #
      def patch_publication_date
        @patch_publication_date ||= if @event.at('patch_publication_date')
          DateTime.strptime(@event.at('patch_publication_date').inner_text, fmt='%Y/%m/%d')
        else
          false
        end
      end

      #
      # Return the event cvss base score.
      #
      # @return [String, false]
      #    Return the event cvss base score.
      #
      def cvss_base_score
        @cvss_base_score ||= if @event.at('cvss_base_score')
          @event.at('cvss_base_score').inner_text.to_f
        else
          false
        end
      end
      
      #
      # Return the event cve.
      #
      # @return [String, false]
      #    Return the event cvss base score.
      #
      def cve
        unless @cve
          @cve = []
          @event.xpath("cve").each do |cve|
            @cve << cve.inner_text
          end
          @cve = false if @cve.empty?
        end
        @cve
      end

      #
      # Return the event bid.
      #
      # @return [String, false]
      #    Return the event bid.
      #
      def bid
        unless @bid
          @bid = []
          @event.xpath("bid").each do |bid|
            @bid << bid.inner_text
          end
          @bid = false if @bid.empty?
        end
        @bid
      end

      #
      # Return other event related references.
      #
      # @return [String, false]
      #    Return the event related references.
      #
      def xref
        unless @xref
          @xref = []
          @event.xpath("xref").each do |xref|
            @xref << xref.inner_text
          end
        end
        @xref
      end

      #
      # Return other event cvss vector.
      #
      # @return [String, false]
      #    Return the event cvss vector.
      #
      def cvss_vector
        @cvss_vector ||= if @event.at('cvss_vector')
          @event.at('cvss_vector').inner_text
        else
          false
        end
      end
      
      #
      # Return the event cpe.
      #
      # @return [String, false]
      #    Return the event cpe.
      #
      def cpe
        unless @cpe
          @cpe = []
          @event.xpath("cpe").each do |cpe|
            @cpe << cpe.inner_text
          end
        end
        @cpe
      end

    end

  end

end
