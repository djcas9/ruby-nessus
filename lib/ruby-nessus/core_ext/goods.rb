class Fixnum
  
  def blank?
    if (self == 0)
      return true
    else
      return false
    end
  end
  
  def severity_in_words
    case self.to_i
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

