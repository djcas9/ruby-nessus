require 'nessus/version'
 
require 'spec_helper'
 
describe Nessus do
  it "should define a VERSION constant" do
    Nessus.should be_const_defined('VERSION')
  end
end
