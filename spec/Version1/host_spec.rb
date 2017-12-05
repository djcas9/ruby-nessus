require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 1: Host' do
  before(:all) do
    @xml = RubyNessus::Version1::XML.new(Helpers::DOT_NESSUS_V1)
    @host = @xml.hosts.first
  end

  it 'should parse the host hostname' do
    expect(@host.hostname).to be_eql('scanme.insecure.org')
  end

  it 'should parse the host start time' do
    expect(@host.scan_start_time.to_s).to be_eql('2009-11-08T02:21:24+00:00')
  end

  it 'should parse the host stop time' do
    expect(@host.scan_stop_time.to_s).to be_eql('2009-11-08T02:31:28+00:00')
  end

  it 'should parse the host runtime' do
    expect(@host.scan_runtime).to be_eql('0 hours 10 minutes and 4 seconds')
  end

  it 'should parse the hosts open ports' do
    expect(@host.open_ports).to be_eql(6)
  end

  it 'should calculate the hosts informational event count' do
    expect(@host.informational_events).to be_eql(5)
  end

  it 'should calculate the hosts low severity event count' do
    expect(@host.low_severity_events).to be_eql(19)
  end

  it 'should calculate the hosts medium severity event count' do
    expect(@host.medium_severity_events).to be_eql(3)
  end

  it 'should calculate the hosts high severity event count' do
    expect(@host.high_severity_events).to be_eql(0)
  end

  it 'should calculate the hosts total event count' do
    expect(@host.event_count).to be_eql(22)
  end

  it 'should to_s return the ip' do
    expect(@host.to_s).to be_eql(@host.ip)
  end

  it 'should ip return the hostname' do
    expect(@host.ip).to be_eql('scanme.insecure.org')
  end

  it 'should mac_addr return the mac address or unknown' do
    expect(@host.mac_addr).to be_eql('(unknown)')
  end
end
