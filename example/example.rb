$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby
require 'rubygems'
require 'ruby-nessus'

Nessus::XML.new("example.nessus") do |scan|
  
  puts "Title: #{scan.report_name}"
  puts "Start Time: #{scan.start_time}"
  puts "Stop Time: #{scan.stop_time}"
  puts "Run Time: #{scan.runtime}"
  puts "Host Count: #{scan.host_count}"

  scan.hosts do |host|
    next if host.event_count.zero?
    puts "Hostname: #{host.hostname}"
    puts "Host Event Count: #{host.event_count}"
    
    puts "High Severity Events:\n"
    
    host.high_severity_events do |high|
      puts "Event Name: #{high.name}" if high.name
      puts "Port: #{high.port}"
    end

  end
end
