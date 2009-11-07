require 'ruby-nessus/nbe'
require 'ruby-nessus/xml'

module Nessus

end

class Fixnum
  
  def blank?
    if (self == 0)
      return true
    else
      return false
    end
  end
  
end

class Object
  def severity_in_words(severity)
    case severity.to_i
    when 0
      return "Informational"
    when 1
      return "Low Severity"
    when 2
      return "Medium Severity"
    when 3
      return "High Severity"
    end
  end
end