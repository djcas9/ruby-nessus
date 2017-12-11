require 'ruby-nessus/log'
require 'ruby-nessus/version1/scan'
require 'ruby-nessus/version2/scan'

require 'nokogiri'
require 'date'
require 'time'

module RubyNessus
  class Parse
    def initialize(file = nil, options = {}, &block)
      doc = file ? File.read(file) : options[:xml]
      @xml = Nokogiri::XML.parse(doc)
      @version = options[:version] || detect_version

      @xml_parser = case @version
                    when 1
                      Version1::XML.new(@xml)
                    when 2
                      Version2::XML.new(@xml)
                    else
                      raise 'Error: Supported .Nessus Version are 1 and 2.'
                    end

      yield(@xml_parser) if block
    end

    # Retrive scan from file
    def scan
      @xml_parser
    end

    # Try to detection version with the XML given
    def detect_version
      if @xml.at('NessusClientData')
        1
      elsif @xml.at('NessusClientData_v2')
        2
      else
        raise 'Error: Supported .Nessus Version are 1 and 2.'
      end
    end
  end
end
