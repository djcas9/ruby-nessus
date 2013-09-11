require 'nessus/log'
require 'nessus/Version1/version1'
require 'nessus/Version2/version2'

require 'nokogiri'
require 'date'
require 'enumerator'
require 'time'

module Nessus

  class Parse

    def initialize(file = nil, options = {}, &block)
      doc = file ? File.read(file) : options[:xml]
      @xml = Nokogiri::XML.parse(doc)
      @version = options[:version]

      if @version
        case @version
          when 1
            block.call(Version1::XML.new(@xml)) if block
          when 2
            block.call(Version2::XML.new(@xml)) if block
          else
            raise "Error: Supported .Nessus Version are 1 and 2."
        end
      else
        if @xml.at('NessusClientData')
          block.call(Version1::XML.new(@xml)) if block
        elsif @xml.at('NessusClientData_v2')
          block.call(Version2::XML.new(@xml)) if block
        else
          raise "Error: Supported .Nessus Version are 1 and 2."
        end
      end

    end

  end
end
