class Fixnum

  def blank?
    if (self.zero?)
      return true
    else
      return false
    end
  end

  def in_words
    case self
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
  
  def high?
    if self == 3
      true
    else
      false
    end
  end
  
  def medium?
    if self == 2
      true
    else
      false
    end
  end
  
  def low?
    if self >= 1
      true
    else
      false
    end
  end

end

class String

  def blank?
    respond_to?(:empty?) ? empty? : !self
  end

end
