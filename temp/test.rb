$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

require 'rubygems'
require 'ruby-nessus'

Nessus::XML.new("2test.nessus") do |scan|

  #test
  #puts scan.ports

  #puts scan.event_percentage_for('high', true) #=> 8%

  puts scan.start_time
  puts scan.stop_time
  puts scan.run_time

  # scan.find_by_hostname("75.28.147.129") do |host|
  #   puts host.scan_start_time
  #   puts host.scan_stop_time
  #   puts host.scan_run_time
  #   host.events do |event|
  #     next if event.severity != 3
  #     puts "Severity: #{event.severity.in_words}"
  #     puts "Port: #{event.port}"
  #     puts "\n"
  #     #puts "\tData: " + event.output
  #   end
  # end

  #
  # scan.hosts_with do |host|
  #   host.event_count
  # end

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
  # Plugin Ids Used In Scan
  #
  # pp scan.plugin_ids.count


  puts "Hosts:"
  scan.hosts do |host|
  
    puts host.hostname
  
    puts "Start Time: " + host.scan_start_time
    puts "Stop Time: " + host.scan_stop_time
  
    puts "Run Time: " + host.scan_run_time
  
    # host.events do |event|
    #   puts event.severity
    #   puts "\n"
    #   puts "Port: " + event.port
    #   puts "Port Service: " + event.port.port_service if event.port.port_service
    #   puts "Port Proto: " + event.port.port_proto if event.port.port_proto
    #   puts "Port Type: " + event.port.port_type if event.port.port_type
    #   puts "\n"
    #   puts "\tData: " + event.output
    # end
    #
  end

end
