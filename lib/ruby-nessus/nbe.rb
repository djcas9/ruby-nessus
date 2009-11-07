module Nessus
  attr_reader :file

  class NBE

    def initialize(file, &block)
      @nbe = File.open(file)

      block.call(self) if block
    end
    
    
  end


end
