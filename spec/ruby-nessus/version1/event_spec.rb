require 'spec_helper'
require 'spec_fixtures/xml'

describe 'Nessus Version 1: Event' do
  before(:all) do
    @xml = RubyNessus::Version1::XML.new(Helpers::DOT_NESSUS_V1)
    @host = @xml.hosts.first
    @bad_event = @host.events.first
    @good_event = @host.events.last
    @bad_port_event = @host.events[25]
  end

  it 'should parse the event name' do
    expect(@good_event.name).to eq 'Backported Security Patch Detection (WWW)'
  end

  it 'should parse the event port' do
    expect(@good_event.port.to_s).to eq 'http (80/tcp)'
  end

  it 'should parse the event port number' do
    expect(@good_event.port.number).to eq '80'
  end

  it 'should parse the event port service' do
    expect(@good_event.port.service).to eq 'http'
  end

  it 'should parse the event port protocol' do
    expect(@good_event.port.protocol).to eq 'tcp'
  end

  it 'should return true if the event port protocol is tcp' do
    expect(@good_event.port.tcp?).to eq true
  end

  it 'should return false if the event port protocol is not udp' do
    expect(@good_event.port.udp?).to eq false
  end

  it 'should parse the event severity' do
    expect(@good_event.severity).to eq 1
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
    expect(@bad_event.name).to eq false
  end

  it 'should use raw_string' do
    expect(@bad_port_event.port.service).to be_falsey
    expect(@bad_port_event.port.to_s).to eq 'general/tcp'
  end
end
