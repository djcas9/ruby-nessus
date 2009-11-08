$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'


Nessus::XML.new("1.nessus") do |scan|

  puts scan.high_severity_count
  puts scan.medium_severity_count
  puts scan.low_severity_count
  puts scan.informational_severity_count
  puts scan.total_event_count
  puts scan.hosts.count

  scan.hosts do |host|
    next if host.event_count.zero?
    puts host.hostname
    puts host.event_count

    puts "--- #{host.informational_severity_events}"

    host.high_severity_events do |high|
      puts high.name if high.name
      puts high.port
    end

  end
end
