module Nessus
  attr_reader :file
  
  class XML
    
    def initialize(file, &block)
      @file = File.open(file)
      @xml = Nokogiri::XML::Reader(@file)
      
      block.call(self) if block
    end
    
    def node_count
      @node_count = 0
      @xml.each { |node| @node_count += 1 }
      @node_count
    end
    
    def list_nodes
      @xml.each do |node|
        puts node.name
      end
    end
    
    def hosts
      
    end
    
  end
  
end