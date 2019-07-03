# frozen_string_literal: true

require 'rainbow'

module RubyNessus
  class Log
    #
    # Formatting
    #
    def self.it(msg = nil)
      warn msg.to_s
    end

    def self.it!(msg = nil)
      warn "\t#{msg}"
    end

    def self.break
      warn "\t"
      warn ''
    end

    def self.end
      warn "\n\n"
    end

    #
    # Headers
    #
    def self.h1(title, msg = nil)
      warn Rainbow("-> #{title}: ").foreground(:green).bright + msg.to_s
    end

    def self.h2(title, msg = nil)
      warn Rainbow("\t#{title}: ").foreground(:blue).bright + msg.to_s
    end

    def self.h3(title, msg = nil)
      warn "\t#{title}: " + Rainbow(msg.to_s).foreground(:blue).underline
    end

    def self.h4(msg = nil)
      warn "\t\t- #{msg}"
    end

    def self.h5(title, msg = nil)
      warn "\t\t- #{title}: #{msg}"
    end

    #
    # Errors
    #
    def self.error(msg = nil)
      warn Rainbow('ERROR: ').foreground(:red).bright + msg.to_s
    end

    def self.warn(msg = nil)
      warn Rainbow('WARNING: ').foreground(:yellow).bright + msg.to_s
    end

    def self.info(msg = nil)
      warn Rainbow('INFO: ').foreground(:green).bright + msg.to_s
    end

    #
    # Event Severities
    #
    def self.informational(title, msg = nil)
      warn Rainbow("\t#{title}: ").foreground(:magenta).bright + msg.to_s
    end

    def self.low(title, msg = nil)
      warn Rainbow("\t#{title}: ").foreground(:green) + msg.to_s
    end

    def self.medium(title, msg = nil)
      warn Rainbow("\t#{title}: ").foreground(:yellow).bright + msg.to_s
    end

    def self.high(title, msg = nil)
      warn Rainbow("\t#{title}: ").foreground(:red).bright + msg.to_s
    end
  end
end
