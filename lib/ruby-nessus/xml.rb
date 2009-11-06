module Nessus
  attr_reader :file
  
  class XML
    
    def initialize(file, &block)
      @file = File.open(file)
      @xml = Nokogiri::XML::Reader(@file)
      
      block.call(self) if block
    end
    
  end
  
end