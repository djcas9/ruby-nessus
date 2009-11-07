$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

require 'rubygems'
require 'ruby-nessus'
require 'pp'

Nessus::XML.new("1test.nessus") do |scan|

  #test
  #puts scan.ports

  puts scan.event_percentage_for('informational', true) + "%"

  scan.find_by_hostname("74.62.126.80") do |host|
    puts host
    puts host.event_count
  end

  # puts scan.high_severity_count
  # 
  # puts scan.medium_severity_count
  # 
  # puts scan.low_severity_count
  # 
  # puts scan.informational_severity_count

  #puts scan.percentage_of_high_severity_events

  # puts "Report Title: " + scan.report_name
  # puts "Start Time: " + scan.start_time
  # puts "Stop Time: " + scan.stop_time
  # #puts scan.run_time
  #
  # puts "\n"
  #
  # puts "Policy Title: " + scan.policy_name
  # puts "Policy Comments: " + scan.policy_comments unless scan.policy_comments.empty?
  #
  # puts "\n"

  #
  # Not Working
  #
  # puts scan.plugin_selection

  # puts "Hosts:"
  # scan.hosts do |host|
  # 
  #   unless host.high_severity_events.blank?
  # 
  #     puts host.hostname
  # 
  #     puts host.start_time
  #     puts host.event_count
  #     puts host.stop_time
  # 
  #     puts host.netbios_name
  # 
  #     puts host.low_severity_events
  # 
  #     host.events do |event|
  #       puts event.severity
  #       puts "\n"
  #       puts "Port: " + event.port
  #       puts "Port Service: " + event.port.port_service if event.port.port_service
  #       puts "Port Proto: " + event.port.port_proto if event.port.port_proto
  #       puts "Port Type: " + event.port.port_type if event.port.port_type
  #       puts "\n"
  #       puts "Port: " + event.port(:proto => true) if event.port(:proto => true)
  #       puts "Port: " + event.port_service if event.port_service
  #       puts "\tData: " + event.output
  #     end
  # 
  #   end
  # 
  # end

end
