require 'ruby-nessus/version'

require 'spec_helper'

describe RubyNessus do
  it "should define a VERSION constant" do
    RubyNessus.should be_const_defined('VERSION')
  end
end
