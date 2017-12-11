require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 1: Host' do
  before(:all) do
    @xml = RubyNessus::Version1::XML.new(Helpers::DOT_NESSUS_V1)
    @host = @xml.hosts.first
  end

  it 'should parse the host hostname' do
    expect(@host.hostname).to eq 'scanme.insecure.org'
  end

  it 'should parse the host start time' do
    expect(@host.scan_start_time.to_s).to eq '2009-11-08T02:21:24+00:00'
  end

  it 'should parse the host stop time' do
    expect(@host.scan_stop_time.to_s).to eq '2009-11-08T02:31:28+00:00'
  end

  it 'should parse the host runtime' do
    expect(@host.scan_runtime).to eq '0 hours 10 minutes and 4 seconds'
  end

  it 'should parse the hosts open ports' do
    expect(@host.open_ports).to eq 6
  end

  it 'should calculate the hosts informational event count' do
    expect(@host.informational_events).to eq 5
  end

  it 'should calculate the hosts low severity event count' do
    expect(@host.low_severity_events).to eq 19
  end

  it 'should calculate the hosts medium severity event count' do
    expect(@host.medium_severity_events).to eq 3
  end

  it 'should calculate the hosts high severity event count' do
    expect(@host.high_severity_events).to eq 0
  end

  it 'should calculate the hosts total event count' do
    expect(@host.event_count).to eq 22
  end

  it 'should to_s return the ip' do
    expect(@host.to_s).to eq @host.ip
  end

  it 'should ip return the hostname' do
    expect(@host.ip).to eq 'scanme.insecure.org'
  end

  it 'should mac_addr return the mac address or unknown' do
    expect(@host.mac_addr).to eq '(unknown)'
  end

  it 'should return the netbios_name' do
    expect(@host.netbios_name).to eq '(unknown)'
  end

  it 'should return the dns_name' do
    expect(@host.dns_name).to eq 'scanme.insecure.org.\\n'
  end

  it 'should return the os_name ' do
    expect(@host.os_name).to eq 'Linux Kernel 2.6 on Red Hat Enterprise Linux 5'
  end
end
