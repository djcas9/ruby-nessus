class Integer

  # Return True if the given severity is high
  # @return [Boolean]
  #   Return True if the given severity is high
  # @example
  #   host.severity.high? #=> true
  def high?
    self == 3
  end

  # Return True if the given severity is medium
  # @return [Boolean]
  #   Return True if the given severity is medium
  # @example
  #   host.severity.medium? #=> true
  def medium?
    self == 2
  end

  # Return True if the given severity is low
  # @return [Boolean]
  #   Return True if the given severity is low
  # @example
  #   host.severity.low? #=> true
  def low?
    self >= 1
  end

  # Return True if the given severity is critical
  # @return [Boolean]
  #   Return True if the given severity is critical
  # @example
  #   host.severity.critical? #=> true
  def critical?
    self == 4
  end
end
