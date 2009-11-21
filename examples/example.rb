$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby
require 'rubygems'
require 'ruby-nessus'

# Ruby-Nessus Example

Nessus::XML.new("example.nessus") do |scan|

  puts "== SCAN ====================\n"
  
  puts "Title: #{scan.title}"
  puts "Policy: #{scan.policy_title}"
  puts "Policy Description: #{scan.policy_notes}"
  puts "Start Time: #{scan.start_time}"
  puts "Stop Time: #{scan.stop_time}"
  puts "Run Time: #{scan.runtime}"
  puts "Host Count: #{scan.host_count}"
  puts "Percentage Of Medium Events: #{scan.event_percentage_for('medium', true)}%"
  
  puts "Low: #{scan.low_severity_count}"
  puts "Medium: #{scan.medium_severity_count}"
  puts "High: #{scan.high_severity_count}"
  puts "Total: #{scan.total_event_count}"
  
  puts "\n"
  puts "== HOSTS ====================\n"
  
  scan.hosts do |host|
    next if host.event_count.zero?
    puts "Hostname: #{host.hostname}"
  
    puts "Start Time: #{host.scan_start_time}" if host.scan_start_time
    puts "Stop Time: #{host.scan_stop_time}" if host.scan_stop_time
    puts "Run Time: #{host.scan_runtime}"
  
    puts "Open Ports: #{host.open_ports}"
    puts "High Severity Events: #{host.high_severity_events}"
    puts "Medium Severity Events: #{host.medium_severity_events}"
    puts "Low Severity Events: #{host.low_severity_events}"
    puts "Total Event Count: #{host.event_count}"
    puts "\n"
    puts "== EVENTS FOR #{host.hostname} ====================\n"
    host.events do |event|
      next unless event.name
      puts "Name: #{event.name}"
      puts "Port: #{event.port}"
      puts "Severity: #{event.severity.in_words}"
    end
    puts "== END #{host.hostname} ====================\n"
  end
end
