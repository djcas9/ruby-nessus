$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby
require 'rubygems'
require 'nessus'

# Ruby-Nessus Example

Nessus::Parse.new('example_v1.nessus') do |scan|  
  
  scan.each_host do |host|
    puts host.ip
    puts host.hostname
    puts host.os_name
    puts host.runtime
    
    #puts host.mac_addr
    # puts host.event_percentage_for('icmp', true)
    # puts host.ports.inspect
    #   
    # puts "\n"
    # 
    host.each_event do |event|
      
      puts "=> #{event.name}" if event.name
      # puts event.synopsis if event.synopsis
      # puts "\n"
      # puts event.output
      # puts "\n"
      # puts event.patch_publication_date.pretty if event.patch_publication_data
      # puts event.see_also unless event.see_also.empty?
      # puts event.synopsis if event.synopsis
      # puts event.solution if event.solution
      
    end
    # 
    # puts "\n"
    # puts "\n"
    
    
  end
  
  
end
