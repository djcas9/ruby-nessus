require 'spec_helper'
require 'spec_fixtures/xml'

describe 'Nessus Version 2: Scan' do
  include Helpers

  before(:all) do
    @xml = RubyNessus::Version2::XML.new(Helpers::DOT_NESSUS_V2)
  end

  it 'should version to be eql at 2' do
    expect(@xml.version).to be_eql(2)
  end

  it 'should parse the scan title' do
    expect(@xml.title).to be_eql('Ruby-Nessus')
  end

  it 'should parse the scan policy title' do
    expect(@xml.policy_title).to be_eql('Ruby-Nessus')
  end

  it 'should parse the scan policy notes' do
    expect(@xml.policy_notes).to be_eql('This is the ruby-nessus example scan using the .nessus version 2 schema.')
  end

  it 'should parse the unique ports' do
    expect(@xml.unique_ports).to be_eql(%w[0 123 21 22 25 443 53 554 7070 80 9090])
  end

  it 'should parse the open ports count' do
    expect(@xml.open_ports_count).to eq 51
  end

  it 'should parse the tcp ports count' do
    expect(@xml.tcp_count).to eq 38
  end

  it 'should parse the udp ports count' do
    expect(@xml.udp_count).to eq 11
  end

  it 'should parse the icmp ports count' do
    expect(@xml.icmp_count).to eq 1
  end

  it 'should parse the scan total host count' do
    expect(@xml.host_count).to be_eql(2)
  end

  it 'should calculate the percentage of low severity events' do
    expect(@xml.event_percentage_for('low', true)).to be_eql('94')
  end

  it 'should calculate the low severity event total' do
    expect(@xml.low_severity_count).to be_eql(47)
  end

  it 'should calculate the percentage of medium severity events' do
    expect(@xml.event_percentage_for('medium', true)).to be_eql('6')
  end

  it 'should calculate the medium severity event total' do
    expect(@xml.medium_severity_count).to be_eql(3)
  end

  it 'should calculate the percentage of high severity events' do
    expect(@xml.event_percentage_for('high', true)).to be_eql('0')
  end

  it 'should calculate the high severity event total' do
    expect(@xml.high_severity_count).to be_eql(0)
  end

  it 'should calculate the critical severity event total' do
    expect(@xml.critical_severity_count).to be_eql(0)
  end

  it 'should calculate the total for all severity events excluding informational' do
    expect(@xml.total_event_count).to be_eql(50)
  end

  it 'should calculate the total for all severity events including informational' do
    expect(@xml.total_event_count(true)).to be_eql(69)
  end

  it 'should target_hosts list the target' do
    expect(@xml.target_hosts).to be_eql(['scanme.insecure.org', 'snorby.org'])
  end

  it 'should find_by_hotsname' do
    @xml.find_by_hostname('scanme.insecure.org') { |host| expect(host.hostname).to eq 'scanme.insecure.org' }
  end
end
