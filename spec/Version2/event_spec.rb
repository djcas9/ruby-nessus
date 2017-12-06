require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 2: Event port' do
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
    @good_event = @host.events.last
  end
  it 'should parse the event name' do
    @good_event.name.should == 'ICMP Timestamp Request Remote Date Disclosure'
  end

  it 'should parse the event port' do
    @good_event.port.to_s.should == 'unknown (0/icmp)'
  end

  it 'should parse the event port number' do
    @good_event.port.number.to_s.should == '0'
  end

  it 'should parse the event port service' do
    @good_event.port.service.to_s.should == 'unknown'
  end

  it 'should parse the event port protocol' do
    @good_event.port.protocol.to_s.should == 'icmp'
  end

  it 'should return true if the event port protocol is icmp' do
    @good_event.port.icmp?.should == true
  end

  it 'should return false if the event port protocol is not udp' do
    @good_event.port.udp?.should == false
  end

  it 'should return false if the event port protocol is not tcp' do
    expect(@good_event.port.tcp?).to be_falsey
  end
end

describe 'Nessus Version 2: Event' do
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
    @good_event = @host.events.last
    @bad_event = @host.events.first
    @medium_event = @host.medium_severity_events.first
    @rich_event = @host.events[22]
  end

  it 'should parse the event severity' do
    @good_event.severity.should == 1
  end

  it 'should return the event plugin output' do
    @good_event.data.should_not be_nil
  end

  it 'should return the event synopsis' do
    @medium_event.synopsis.should == 'The remote web server encrypts traffic using an obsolete protocol.'
  end

  it 'should return the event description' do
    @medium_event.description.should == "The remote web server accepts connections encrypted using Secure\nHyperText Transfer Protocol (S-HTTP), a cryptographic layer that was\ndefined in 1999 by RFC 2660 and never widely implemented."
  end

  it 'should return the event solution' do
    @medium_event.solution.should == "Rare or obsolete code is often poorly tested. Thus, it would be\nsafer to disable support for S-HTTP and use HTTPS instead."
  end

  it 'should return the event risk' do
    @medium_event.risk.should == 'Medium'
  end

  it 'should return the event output' do
    @good_event.output.should == "The difference between the local and remote clocks is 1 second.\n"
  end

  it 'should return false for the event output' do
    expect(@medium_event.output).to be_falsey
  end

  it 'should return false for the event plugin version' do
    @medium_event.version.should == '$Revision: 1.9 $'
  end

  it 'should return the see_also information for the event' do
    @medium_event.see_also.should == ['http://tools.ietf.org/html/rfc2660']
  end

  it 'should return the patch publication date' do
    expect(@rich_event.patch_publication_date).to be_kind_of(DateTime)
  end

  it 'should return false if there is no patch publication date' do
    expect(@medium_event.patch_publication_date).to be_falsey
  end

  it 'should return the cvss base score' do
    @medium_event.cvss_base_score.should == 5.0
  end

  it 'should return the cve score' do
    expect(@rich_event.cve.first).to be_kind_of(String)
    expect(@rich_event.cve.first).not_to be_blank
  end

  it 'should return falsey if no cve' do
    expect(@medium_event.cve).to be_falsey
  end

  it 'should not return bid if its not here' do
    expect(@medium_event.bid).to be_falsey
  end

  it 'should return the bid' do
    expect(@rich_event.bid.first).to eq '36935'
  end

  it 'should retun an empty tab if there is not other ref' do
    expect(@medium_event.xref).to be_empty
  end

  it 'should return other related references' do
    expect(@rich_event.xref.first).to eq 'OSVDB:59968'
  end

  it 'should return cvss_vector' do
    @medium_event.cvss_vector.should == 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  end

  it 'should have a plugin_id' do
    expect(@good_event.plugin_id).to be_kind_of(Integer)
  end

  it 'should have a plugin_id' do
    expect(@good_event.plugin_family).to be_kind_of(String)
    expect(@good_event.plugin_family).not_to be_blank
  end

  it 'should have a cpe Array (empty if no cpe)' do
    expect(@good_event.cpe).to be_kind_of(Array)
  end

  # Bad Event

  it 'should return false if the event name is nil' do
    @bad_event.name.should == false
  end
end
describe 'Nessus Version 2: Event severity' do
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
    @medium_event = @host.medium_severity_events.first
  end

  it 'should not have a informational severity' do
    expect(@medium_event.informational?).to be false
  end

  it 'should not have a low severity' do
    expect(@medium_event.low?).to be false
  end

  it 'should have a medium severity' do
    expect(@medium_event.medium?).to be true
  end

  it 'should have not have a high severity' do
    expect(@medium_event.high?).to be false
  end

  it 'should have not have a high severity' do
    expect(@medium_event.critical?).to be false
  end

  it 'should have not have a high severity' do
    expect(@medium_event.critical?).to be false
  end
end
