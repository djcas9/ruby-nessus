require 'ruby-nessus/xml'

require 'spec_helper'
require 'helpers/xml'


describe "XML" do
  include Helpers

  before(:all) do
    @xml = Nessus::XML.new(Helpers::DOT_NESSUS)
  end
  
  it "should parse the scan title" do
    @xml.title == 'Ruby-Nessus Example Policy'
  end
  
  it "should parse the scan start name" do
    @xml.time == '2009-11-08T02:21:23+00:00'
  end
  
  it "should parse the scan stop name" do
    @xml.time == '2009-11-08T02:31:29+00:00'
  end

  it "should parse the scan policy title" do
     @xml.policy_title == '2009-11-08T02:21:23+00:00'
  end

  it "should parse the scan policy description/comments" do
    @xml.policy_notes == "This is an example .nessus file for testing the Ruby-Nessus gem."
  end

end
