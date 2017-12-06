require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 1: Event' do
  before(:all) do
    @xml = RubyNessus::Version1::XML.new(Helpers::DOT_NESSUS_V1)
    @host = @xml.hosts.first
    @bad_event = @host.events.first
    @good_event = @host.events.last
    @bad_port_event = @host.events[25]
  end

  it 'should parse the event name' do
    @good_event.name.should == 'Backported Security Patch Detection (WWW)'
  end

  it 'should parse the event port' do
    @good_event.port.to_s.should == 'http (80/tcp)'
  end

  it 'should parse the event port number' do
    @good_event.port.number.should == '80'
  end

  it 'should parse the event port service' do
    @good_event.port.service.should == 'http'
  end

  it 'should parse the event port protocol' do
    @good_event.port.protocol.should == 'tcp'
  end

  it 'should return true if the event port protocol is tcp' do
    @good_event.port.tcp?.should == true
  end

  it 'should return false if the event port protocol is not udp' do
    @good_event.port.udp?.should == false
  end

  it 'should parse the event severity' do
    @good_event.severity.should == 1
  end

  it 'should return the event plugin output' do
    expect(@good_event.data).not_to be nil
  end

  it 'should return falsey if not data' do
    expect(@bad_event.data).to be_falsey
  end

  it 'should have a plugin_id' do
    expect(@good_event.plugin_id).to eq 39_521
  end

  # Bad Event

  it 'should return false if the event name is nil' do
    @bad_event.name.should == false
  end

  it 'should use raw_string' do
    expect(@bad_port_event.port.service).to be_falsey
    @bad_port_event.port.to_s.should == 'general/tcp'
  end
end
