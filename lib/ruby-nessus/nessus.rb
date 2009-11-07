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