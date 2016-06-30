require 'spec_helper'
require 'helpers/xml'

describe "Nessus Version 2: Event" do
  
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
    @bad_event = @host.events.first
    @good_event = @host.events.last
    @medium_event = @host.medium_severity_events.first
  end
  
  it "should parse the event name" do
    @good_event.name.should == "ICMP Timestamp Request Remote Date Disclosure"
  end
  
  it "should parse the event port" do
    @good_event.port.to_s.should == "unknown (0/icmp)"
  end
  
  it "should parse the event port number" do
    @good_event.port.number.to_s.should == '0'
  end
  
  it "should parse the event port service" do
    @good_event.port.service.to_s.should == "unknown"
  end
  
  it "should parse the event port protocol" do
    @good_event.port.protocol.to_s.should == "icmp"
  end
  
  it "should return true if the event port protocol is icmp" do
    @good_event.port.icmp?.should == true
  end
  
  it "should return false if the event port protocol is not udp" do
    @good_event.port.udp?.should == false
  end
  
  it "should parse the event severity" do
    @good_event.severity.should == 1
  end
  
  it "should return the event severity in words" do
    @good_event.severity.in_words.should == "Low Severity"
  end
  
  it "should return the event plugin output" do
    @good_event.data.should_not be_nil
  end
  
  it "should return the event synopsis" do
    @medium_event.synopsis.should == 'The remote web server encrypts traffic using an obsolete protocol.'
  end
  
  it "should return the event description" do
    @medium_event.description.should == "The remote web server accepts connections encrypted using Secure\nHyperText Transfer Protocol (S-HTTP), a cryptographic layer that was\ndefined in 1999 by RFC 2660 and never widely implemented."
  end
  
  it "should return the event solution" do
    @medium_event.solution.should == "Rare or obsolete code is often poorly tested. Thus, it would be\nsafer to disable support for S-HTTP and use HTTPS instead."
  end
  
  it "should return the event risk" do
    @medium_event.risk.should == "Medium"
  end
  
  it "should return the event output" do
    @good_event.output.should == "The difference between the local and remote clocks is 1 second.\n"
  end
  
  it "should return false for the event output" do
    @medium_event.output.should == false
  end
  
  it "should return false for the event plugin version" do
    @medium_event.version.should == '$Revision: 1.9 $'
  end
  
  it "should return the see_also information for the event" do
    @medium_event.see_also.should == ["http://tools.ietf.org/html/rfc2660"]
  end
  
  it "should return the patch publication date" do
    @medium_event.patch_publication_date.should == false
  end
  
  it "should return the cvss base score" do
    @medium_event.cvss_base_score.should == 5.0
  end
  
  it "should return the cve score" do
    @medium_event.cve.should == false
  end
  
  it "should return the bid" do
    @medium_event.bid.should == false
  end
  
  it "should return other related references" do
    @medium_event.xref.should == []
  end

  it "should return cvss_vector" do
    @medium_event.cvss_vector.should == 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  end
  
  # Bad Event
  
  it "should return false if the event name is nil" do
    @bad_event.name.should == false
  end
  
end