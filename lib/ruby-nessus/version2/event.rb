# frozen_string_literal: true

require 'ruby-nessus/version2/port'

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
      # @return [Integer]
      #    Return the event severity.
      #
      # @example
      #   event.severity          #=> 3
      #
      def severity
        @severity ||= @event.at('@severity').inner_text.to_i
      end
      # New matches for Baseline

      def compliance_info
        @event.xpath('.//*[name()="cm:compliance-info"]')
      end
      def item_id
        @item_id ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/item_id: (.*)/).captures.first
      end
      def baseline
        @baseline ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/baseline: (.*)/).captures.first
      end
      def item_description
        @item_description ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/item_description: (.*)/).captures.first
      end
      def threats
        @threats ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/threats: (.*)/).captures.first
      end
      def impacts
        @impacts ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/impacts: (.*)/).captures.first
      end
      def manual_setup
        @manual_setup ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/manual_setup: (.*)/).captures.first
      end
      def threat_level
        @threat_level ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/threat_level: (.*)/).captures.first
      end
      def impact_level
        @impact_level ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/impact_level: (.*)/).captures.first
      end
      def check_type
        @check_type ||= @event.xpath('.//*[name()="cm:compliance-info"]').text.match(/expected_value: (.*)/).captures.first
      end
      def compliance_uname
        @compliance_uname ||= @event.xpath('.//*[name()="cm:compliance-uname"]').children.text
      end

      def compliance_check_name
        @compliance_check_name ||= @event.xpath('.//*[name()="cm:compliance-check-name"]').children.text
      end

      def compliance_result
        @compliance_result ||= @event.xpath('.//*[name()="cm:compliance-result"]').children.text
      end

      def remote_value
        @remote_value ||= @event.xpath('.//*[name()="cm:compliance-actual-value"]').children.text
      end
      
      def policy_value
        @policy_value ||= @event.xpath('.//*[name()="cm:compliance-policy-value"]').children.text
      end
      
      def check_name
        @check_name ||= @event.xpath('.//*[name()="cm:compliance-check-name"]').children.text
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
      # @return [Integer]
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
      # @return [String, nil]
      #    Return the event name (plugin_name)
      #
      # @example
      #   event.plugin_name   #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #   event.name          #=> "PHP < 5.2.4 Multiple Vulnerabilities"
      #
      def plugin_name
        @plugin_name ||= @event.at('@pluginName')&.inner_text unless @event.at('@pluginName').inner_text.empty?
      end
      alias name plugin_name
      #
      # Return the event object plugin type (plugin_type)
      #
      # @return [String, nil]
      #    Return the event object plugin type (plugin_type)
      #
      # @example
      #   event.plugin_type   #=> "remote"
      #
      def plugin_type
        @plugin_type ||= @event.at('plugin_type')&.inner_text
      end

      #
      # Return the event synopsis.
      #
      # @return [String, nil]
      #    Return the event synopsis.
      #
      def synopsis
        @synopsis ||= @event.at('synopsis')&.inner_text
      end

      #
      # Return the event description.
      #
      # @return [String, nil]
      #    Return the event description.
      #
      def description
        @description ||= @event.at('description')&.inner_text
      end

      #
      # Return the event solution.
      #
      # @return [String, nil]
      #    Return the event solution.
      #
      def solution
        @solution ||= @event.at('solution')&.inner_text
      end

      #
      # Return the event risk.
      #
      # @return [String, nil]
      #    Return the event risk.
      #
      def risk
        @risk_factor ||= @event.at('risk_factor')&.inner_text
      end

      #
      # Return the event plugin output.
      #
      # @return [String, nil]
      #    Return the event plugin output.
      #
      def output
        @plugin_output ||= @event.at('plugin_output')&.inner_text
      end
      alias data output
      alias plugin_output output

      #
      # Return the event plugin version.
      #
      # @return [String, nil]
      #    Return the event plugin version.
      #
      def version
        @plugin_version ||= @event.at('plugin_version')&.inner_text
      end
      alias plugin_version version

      #
      # Return the event reference links.
      #
      # @return [Array<String>]
      #    Return the event reference links.
      #
      def see_also
        @see_also ||= @event.at('see_also')&.inner_text&.split("\n")
      end
      alias links see_also
      alias more see_also
      alias references see_also

      #
      # Return the event vulnerability publication date.
      #
      # @return [Time, nil]
      #    Return the event vulnerability publication date.
      #
      def vuln_publication_date
        @vuln_publication_date ||= Time.parse(@event.at('vuln_publication_date').inner_text + ' UTC') if @event.at('vuln_publication_date')
      end

      #
      # Return the event patch publication date.
      #
      # @return [Time, nil]
      #    Return the event patch publication date.
      #
      def patch_publication_date
        @patch_publication_date ||= Time.parse(@event.at('patch_publication_date').inner_text + ' UTC') if @event.at('patch_publication_date')
      end

      #
      # Return the event cvss base score.
      #
      # @return [float, nil]
      #    Return the event cvss base score.
      #
      def cvss_base_score
        @cvss_base_score ||= @event.at('cvss_base_score')&.inner_text.to_f
      end

      def cvss3_base_score
        @cvss3_base_score ||= @event.at('cvss3_base_score')&.inner_text.to_f
      end
      #
      # Return the event cvss temporal score.
      #
      # @return [float, nil]
      #    Return the event cvss temporal score.
      #
      def cvss_temporal_score
        @cvss_temporal_score ||= @event.at('cvss_temporal_score')&.inner_text.to_f
      end

      def cvss3_temporal_score
        @cvss_temporal_score ||= @event.at('cvss3_temporal_score')&.inner_text.to_f
      end

      #
      # Return the event cve.
      #
      # @return [Array<String>, nil]
      #    Return the event cvss base score.
      #
      def cve
        unless @cve
          @cve = []
          @event.xpath('cve').each do |cve|
            @cve << cve.inner_text
          end
          @cve = nil if @cve.empty?
        end
        @cve
      end

      #
      # Return the event bid.
      #
      # @return [Array<String>, nil]
      #    Return the event bid.
      #
      def bid
        unless @bid
          @bid = []
          @event.xpath('bid').each do |bid|
            @bid << bid.inner_text
          end
          @bid = nil if @bid.empty?
        end
        @bid
      end

      #
      # Return other event related references.
      #
      # @return [Array<String>]
      #    Return the event related references.
      #
      def xref
        unless @xref
          @xref = []
          @event.xpath('xref').each do |xref|
            @xref << xref.inner_text
          end
        end
        @xref
      end

      #
      # Return other event cvss vector.
      #
      # @return [String, nil]
      #    Return the event cvss vector.
      #
      def cvss_vector
        @cvss_vector ||= @event.at('cvss_vector')&.inner_text
      end

      def cvss3_vector
        @cvss3_vector ||= @event.at('cvss3_vector')&.inner_text#.gsub("CVSS:3.0/","")
      end

      def cvss_temporal_vector
        @cvss_vector ||= @event.at('cvss_temporal_vector')&.inner_text
      end

      def cvss3_temporal_vector
        @cvss3_vector ||= @event.at('cvss3_temporal_vector')&.inner_text#.gsub("CVSS:3.0/","")
      end

      #
      # Return the event cpe.
      #
      # @return [Array<String>]
      #    Return the event cpe.
      # 
      def cpe
        unless @cpe
          @cpe = []
          @event.xpath('cpe').each do |cpe|
            @cpe |= cpe.inner_text.split("\n")
          end
        end
        @cpe
      end

      #
      # Return event exploitability ease.
      #
      # @return [String, nil]
      #    Return the event exploitability ease.
      #
      def exploitability_ease
        @exploitability_ease ||= @event.at('exploitability_ease')&.inner_text
      end

      #
      # Return event exploit available.
      #
      # @return [Boolean]
      #    Return the event exploit available.
      #
      def exploit_available
        @exploit_available ||= @event.at('exploit_available')&.inner_text == 'true'
      end

      #
      # Return if an exploit exists in the Immunity CANVAS framework.
      #
      # @return [Boolean]
      #    Return the event exploit framework canvas.
      #
      def exploit_framework_canvas
        @exploit_framework_canvas ||= @event.at('exploit_framework_canvas')&.inner_text == 'true'
      end

      #
      # Return the name of the CANVAS exploit package
      #
      # @return [String, nil]
      #    Return the canvas_package.
      #
      def canvas_package
        @canvas_package ||= @event.at('canvas_package')&.inner_text
      end

      #
      # Return if an exploit exploit exists in the Metasploit framework
      #
      # @return [Boolean]
      #    Return the event exploit framework metasploit.
      #
      def exploit_framework_metasploit
        @exploit_framework_metasploit ||= @event.at('exploit_framework_metasploit')&.inner_text == 'true'
      end

      #
      # Return name of the Metasploit exploit module.
      #
      # @return [String, nil]
      #    Return the metasploit_name.
      #
      def metasploit_name
        @metasploit_name ||= @event.at('metasploit_name')&.inner_text
      end

      #
      # Return if an exploit exploit exists in the CORE Impact framework
      #
      # @return [Boolean]
      #    Return the event exploit framework core.
      #
      def exploit_framework_core
        @exploit_framework_core ||= @event.at('exploit_framework_core')&.inner_text == 'true'
      end
    end
  end
end
