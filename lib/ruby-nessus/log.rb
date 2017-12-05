require 'rainbow'
module RubyNessus
  
  class Log
    
    #
    # Formatting
    #
    def self.it(msg=nil)
      STDERR.puts "#{msg}"
    end
    
    def self.it!(msg=nil)
      STDERR.puts "\t#{msg}"
    end
    
    def self.break
      STDERR.puts "\t"
      STDERR.puts ""
    end
    
    def self.end
      STDERR.puts "\n\n"
    end
    
    #
    # Headers
    #
    def self.h1(title, msg=nil)
      STDERR.puts "-> #{title}: ".foreground(:green).bright + "#{msg}"
    end
    
    def self.h2(title, msg=nil)
      STDERR.puts "\t#{title}: ".foreground(:blue).bright + "#{msg}"
    end
    
    def self.h3(title, msg=nil)
      STDERR.puts "\t#{title}: " + "#{msg}".foreground(:blue).underline
    end
    
    def self.h4(msg=nil)
      STDERR.puts "\t\t- #{msg}"
    end
    
    def self.h5(title, msg=nil)
      STDERR.puts "\t\t- #{title}: #{msg}"
    end
    
    #
    # Errors
    #
    def self.error(msg=nil)
      STDERR.puts "ERROR: ".foreground(:red).bright + "#{msg}"
    end
    
    def self.warn(msg=nil)
      STDERR.puts "WARNING: ".foreground(:yellow).bright + "#{msg}"
    end
    
    def self.info(msg=nil)
      STDERR.puts "INFO: ".foreground(:green).bright + "#{msg}"
    end 
    
    #
    # Event Severities
    #
    def self.informational(title, msg=nil)
      STDERR.puts "\t#{title}: ".foreground(:magenta).bright + "#{msg}"
    end

    def self.low(title, msg=nil)
      STDERR.puts "\t#{title}: ".foreground(:green) + "#{msg}"
    end

    def self.medium(title, msg=nil)
      STDERR.puts "\t#{title}: ".foreground(:yellow).bright + "#{msg}"
    end

    def self.high(title, msg=nil)
      STDERR.puts "\t#{title}: ".foreground(:red).bright + "#{msg}"
    end
    
  end
  
end