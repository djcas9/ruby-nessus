require 'spec_helper'
require 'helpers/xml'

describe "Host" do
  
  before(:all) do
    @xml = Nessus::XML.new(Helpers::DOT_NESSUS)
    @host = @xml.all_hosts.first
  end
  
  it "should parse the host hostname" do
    @host.hostname.should == 'scanme.insecure.org'
  end
  
  it "should parse the host start time" do
    @host.scan_start_time.to_s.should == '2009-11-08T02:21:24+00:00'
  end
  
  it "should parse the host stop time" do
    @host.scan_stop_time.to_s.should == '2009-11-08T02:31:28+00:00'
  end
  
  it "should parse the host runtime" do
    @host.scan_runtime.should == '0 hours 10 minutes and 4 seconds'
  end
  
  it "should parse the hosts open ports" do
    @host.open_ports.should == 6
  end
  
  it "should calculate the hosts informational event count" do
    @host.informational_events.should == 5
  end
  
  it "should calculate the hosts low severity event count" do
    @host.low_severity_events.should == 19
  end
  
  it "should calculate the hosts medium severity event count" do
    @host.medium_severity_events.should == 3
  end
  
  it "should calculate the hosts high severity event count" do
    @host.high_severity_events.should == 0
  end
  
  it "should calculate the hosts total event count" do
    @host.event_count.should == 22
  end
  
end