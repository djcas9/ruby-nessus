$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby
require 'rubygems'
require 'ruby-nessus'

# Ruby-Nessus Example

Nessus::XML.new("example.nessus") do |scan|
  
  
  puts scan.runtime
  
  puts "Title: #{scan.report_name}"
  puts "Policy: #{puts scan.policy_name}"
  puts "Policy Description:\n#{puts scan.policy_name}"
  puts "Start Time: #{scan.start_time}"
  puts "Stop Time: #{scan.stop_time}"
  puts "Run Time: #{scan.runtime}"
  puts "Host Count: #{scan.host_count}"
  puts "Percentage Of Medium Events: #{scan.event_percentage_for('medium', true)}%"
  
  
  scan.hosts do |host|
    puts "Hostname: #{host.hostname}"
    puts "Open Ports: #{host.scanned_ports_count}"
    puts "High Severity Events: #{host.high_severity_events}"
    puts "Medium Severity Events: #{host.medium_severity_events}"
    puts "Low Severity Events: #{host.low_severity_events}"
    puts "Total Event Count: #{host.event_count}"
    puts "\n"
    
    host.events do |event|
      next unless event.name
      puts "Name: #{event.name}"
      puts "Port: #{event.port}"
      puts "Severity: #{event.severity.in_words}"
    end
  
  end
end
