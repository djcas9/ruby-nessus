require 'spec_helper'
require 'helpers/xml'

describe "Nessus Version 2: Host" do
  
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
  end
  
  it "should parse the host hostname" do
    @host.hostname.should == 'snorby.org'
  end
  
  it "should parse the host start time" do
    @host.start_time.to_s.should == '2009-12-11T02:57:52+00:00'
  end
  
  it "should parse the host stop time" do
    @host.stop_time.to_s.should == '2009-12-11T03:25:29+00:00'
  end
  
  it "should parse the host runtime" do
    @host.runtime.should == '1 hours 32 minutes and 23 seconds'
  end
  
  it "should parse the hosts open ports" do
    @host.open_ports.should == 37
  end
  
  it "should calculate the hosts informational event count" do
    @host.informational_severity_count.should == 12
  end
  
  it "should calculate the hosts low severity event count" do
    @host.low_severity_count.should == 34
  end
  
  it "should calculate the hosts medium severity event count" do
    @host.medium_severity_count.should == 1
  end
  
  it "should calculate the hosts high severity event count" do
    @host.high_severity_count.should == 0
  end

  it "should calculate the hosts critical severity event count" do
    @host.critical_severity_count.should == 0
  end
  
  it "should calculate the hosts total event count" do
    @host.total_event_count.should == 35
  end
  
  it "should calculate the hosts total event count with informational events" do
    @host.total_event_count(true).should == 47
  end
  
end
