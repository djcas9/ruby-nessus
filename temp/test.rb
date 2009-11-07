$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'


Nessus::XML.new("1.nessus") do |scan|

  scan.hosts do |host|
    next if host.event_count.zero?
    puts host.hostname
    puts host.event_count

    host.events do |event|
      next if !event.severity.low?
      puts event.name if event.name
      puts event.port
      puts event.severity.in_words
      puts event.plugin_id
      puts event.data
    end

  end

end



# Nessus::XML.new("2.nessus") do |scan|
# 
#   #test
#   #puts scan.ports
# 
#   puts scan.event_percentage_for('low', true) #=> 8%
# 
#   puts scan.start_time
#   puts scan.stop_time
#   puts scan.run_time
# 
#   scan.find_by_hostname("75.28.147.129") do |host|
#     puts host.scan_start_time
#     puts host.scan_stop_time
#     puts host.scan_run_time
#     host.events do |event|
#       next if event.severity != 3
#       puts "Severity: #{event.severity.in_words}"
#       puts "Port: #{event.port}"
#       puts "\n"
#       #puts "\tData: " + event.output
#     end
#   end
# 
#   puts scan.high_severity_count
# 
#   puts scan.medium_severity_count
# 
#   puts scan.low_severity_count
# 
#   puts scan.informational_severity_count
# 
#   puts scan.total_event_count
#   
#   puts scan.hosts.count
# 
#   puts scan.percentage_of_high_severity_events
# 
#   puts "Report Title: " + scan.report_name
#   puts "Start Time: " + scan.start_time
#   puts "Stop Time: " + scan.stop_time
#   #puts scan.run_time
#   
#   puts "\n"
#   
#   puts "Policy Title: " + scan.policy_name
#   puts "Policy Comments: " + scan.policy_comments unless scan.policy_comments.empty?
#   
#   puts "\n"
# 
#   
#   Plugin Ids Used In Scan
#   
#   pp scan.plugin_ids.count
# 
# 
#   puts "Hosts:"
#   scan.hosts do |host|
#   
#     puts host.hostname
#     puts "Start Time: " + host.scan_start_time
#     puts "Stop Time: " + host.scan_stop_time
#     puts "Run Time: " + host.scan_run_time
#   
#     host.events do |event|
#       next if %(0 1).include?(event.severity)
#       puts event.name if event.name
#       puts "\n"
#       puts "Port: " + event.port.to_s
#       # if event.port
#       #   puts "Port Service: " + event.port.port_service if event.port.port_service
#       #   puts "Port Proto: " + event.port.port_proto if event.port.port_proto
#       #   puts "Port Type: " + event.port.port_type if event.port.port_type
#       # end
#       puts "\n"
#       puts "\tData: " + event.output
#     end
#   
#   end
# 
# end
