require 'spec_helper'
require 'helpers/xml'

describe 'Nessus Version 1: Scan' do
  include Helpers

  before(:all) do
    @xml = RubyNessus::Version1::XML.new(Helpers::DOT_NESSUS_V1)
  end

  it 'should parse the scan title' do
    @xml.title.should == 'Ruby-Nessus Example Policy'
  end

  it 'should parse the scan time' do
    @xml.time.to_s.should == '2009-11-08T02:21:22+00:00'
  end

  it 'should parse the scan policy title' do
    @xml.policy_title.should == 'Ruby-Nessus Example Policy'
  end

  it 'should parse the scan policy notes' do
    @xml.policy_notes.should == 'This is an example .nessus file for testing the Ruby-Nessus gem.'
  end

  it 'should parse the scan start time' do
    @xml.start_time.to_s.should == '2009-11-08T02:21:23+00:00'
  end

  it 'should parse the scan stop time' do
    @xml.stop_time.to_s.should == '2009-11-08T02:31:29+00:00'
  end

  it 'should parse the scan runtime' do
    @xml.runtime.should == '0 hours 10 minutes and 6 seconds'
  end

  it 'should parse the scan total host count' do
    @xml.host_count.should == 1
  end

  it 'should calculate the percentage of low severity events' do
    @xml.event_percentage_for('low', true).should == '86'
  end

  it 'should calculate the low severity event total' do
    @xml.low_severity_count.should == 19
  end

  it 'should calculate the percentage of medium severity events' do
    @xml.event_percentage_for('medium', true).should == '14'
  end

  it 'should calculate the medium severity event total' do
    @xml.medium_severity_count.should == 3
  end

  it 'should calculate the percentage of high severity events' do
    @xml.event_percentage_for('high', true).should == '0'
  end

  it 'should calculate the high severity event total' do
    @xml.high_severity_count.should == 0
  end

  it 'should calculate the total for all severity events' do
    @xml.total_event_count.should == 22
  end

  it 'should target_hosts list the target' do
    expect(@xml.target_hosts).to eq ['scanme.insecure.org']
  end

  it 'should be version 1' do
    expect(@xml.version).to eq 1
  end

  it 'should return the plugin ids' do
    expect(@xml.plugin_ids.length).to eq 31_507
  end

  it 'should return the plugins' do
    expect(@xml.plugins).to be_kind_of(Array)
    expect(@xml.plugins).not_to be_blank
  end

  it 'should parse the unique ports' do
    expect(@xml.unique_ports).to eq ['arcp (7070/tcp)', 'domain (53/tcp)', 'domain (53/udp)', 'ftp (21/tcp)', 'general/tcp', 'general/udp', 'http (80/tcp)', 'rtsp (554/tcp)']
  end

  it 'should find_by_hotsname' do
    @xml.find_by_hostname('scanme.insecure.org') { |host| expect(host.hostname).to eq 'scanme.insecure.org' }
  end

end
