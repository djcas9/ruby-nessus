class Fixnum

  def blank?
    if (self.zero?)
      return true
    else
      return false
    end
  end

  def in_words
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

class String

  def blank?
    respond_to?(:empty?) ? empty? : !self
  end

end
