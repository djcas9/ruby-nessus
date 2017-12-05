require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 2: Host' do
  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
    @host = @xml.hosts.first
  end

  it 'should parse the host hostname' do
    expect(@host.hostname).to be_eql('snorby.org')
  end

  it 'should parse the host start time' do
    expect(@host.start_time.to_s).to be_eql('2009-12-11T02:57:52+00:00')
  end

  it 'should parse the host stop time' do
    expect(@host.stop_time.to_s).to be_eql('2009-12-11T03:25:29+00:00')
  end

  it 'should parse the host runtime' do
    expect(@host.runtime).to be_eql('1 hours 32 minutes and 23 seconds')
  end

  it 'should parse the hosts open ports' do
    expect(@host.open_ports).to be_eql(37)
  end

  it 'should calculate the hosts informational event count' do
    expect(@host.informational_severity_count).to be_eql(12)
  end

  it 'should calculate the hosts low severity event count' do
    expect(@host.low_severity_count).to be_eql(34)
  end

  it 'should calculate the hosts medium severity event count' do
    expect(@host.medium_severity_count).to be_eql(1)
  end

  it 'should calculate the hosts high severity event count' do
    expect(@host.high_severity_count).to be_eql(0)
  end

  it 'should calculate the hosts critical severity event count' do
    expect(@host.critical_severity_count).to be_eql(0)
  end

  it 'should calculate the hosts total event count' do
    expect(@host.total_event_count).to be_eql(35)
  end

  it 'should calculate the hosts total event count with informational events' do
    expect(@host.total_event_count(true)).to be_eql(47)
  end

  it 'should to_s return the ip address' do
    expect(@host.to_s).to be_eql(@host.ip)
  end

  it 'should ip return the ip address' do
    expect(@host.ip).to be_eql('173.45.230.150')
  end

  it 'should mac_addr return the mac address if exist else nil' do
    expect(@host.mac_addr).to be_nil
  end

  it 'should os_name return the os name' do
    expect(@host.os_name).to be_eql('NetBSD 3.0')
  end

  it 'should tcp_count return the tcp event count' do
    expect(@host.tcp_count).to be_eql(32)
  end

  it 'should udp_count return the udp event count' do
    expect(@host.udp_count).to be_eql(2)
  end

  it 'should icmp_count return the icmp event count' do
    expect(@host.icmp_count).to be_eql(1)
  end
end
