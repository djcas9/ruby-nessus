module Nessus
  
  class Log
    
    def self.it(msg)
      STDERR.puts "#{msg}"
    end
    
    def self.error(msg)
      STDERR.puts "ERROR: #{msg}"
    end
    
    def self.warn(msg)
      STDERR.puts "WARNING: #{msg}"
    end
    
    def self.info(msg)
      STDERR.puts "ERROR: #{msg}"
    end 
    
  end
  
end