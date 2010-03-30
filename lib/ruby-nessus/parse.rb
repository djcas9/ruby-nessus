require 'ruby-nessus/Version1/version1'
require 'ruby-nessus/Version2/version2'

require 'nokogiri'
require 'date'
require 'enumerator'
require 'time'

module Nessus

  class Parse

    def initialize(file, attributes={}, &block)
      @file = file
      @version = attributes[:version] || 2

      case @version

        when 1
          block.call(Version1::XML.new(file)) if block
        when 2
          block.call(Version2::XML.new(file)) if block
        else
          raise "Error: Supported .Nessus Version are 1 and 2."
      end

    end

  end
end
