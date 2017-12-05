require 'spec_helper'
require 'helpers/xml'

describe "Nessus Version 2: Scan" do
  include Helpers

  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
  end

  it "should parse the scan title" do
    @xml.title.should == 'Ruby-Nessus'
  end

  it "should parse the scan policy title" do
    @xml.policy_title.should == 'Ruby-Nessus'
  end

  it "should parse the scan policy notes" do
    @xml.policy_notes.should == "This is the ruby-nessus example scan using the .nessus version 2 schema."
  end

  it "should parse the scan total host count" do
    @xml.host_count.should == 2
  end

  it "should calculate the percentage of low severity events" do
    @xml.event_percentage_for("low", true).should == "94"
  end

  it "should calculate the low severity event total" do
    @xml.low_severity_count.should == 47
  end

  it "should calculate the percentage of medium severity events" do
    @xml.event_percentage_for("medium", true).should == "6"
  end

  it "should calculate the medium severity event total" do
    @xml.medium_severity_count.should == 3
  end

  it "should calculate the percentage of high severity events" do
    @xml.event_percentage_for("high", true).should == "0"
  end

  it "should calculate the high severity event total" do
    @xml.high_severity_count.should == 0
  end

  it "should calculate the critical severity event total" do
    @xml.critical_severity_count.should == 0
  end

  it "should calculate the total for all severity events excluding informational" do
    @xml.total_event_count.should == 50
  end

  it "should calculate the total for all severity events including informational" do
    @xml.total_event_count(true).should == 69
  end
end
