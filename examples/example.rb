$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))

#!/usr/bin/env ruby
require 'rubygems'
require 'ruby-nessus'

# Ruby-Nessus Example

Nessus::Parse.new('example_v2.nessus', :version => 2) do |scan|  
  
  #puts scan.title
  #puts scan.policy_title
  #puts scan.policy_notes
  
  #puts scan.total_event_count(true)
  
  # puts scan.tcp_count
  # puts scan.udp_count
  # puts scan.icmp_count
  
  # puts scan.informational_severity_count
  # puts scan.high_severity_count
  # puts scan.medium_severity_count
  # puts scan.low_severity_count
  
  scan.find_by_hostname('snorby') do |host|
    
    puts host.hostname
    puts host.ip
      
    host.medium_severity_events do |event|
      puts event.family
      
      puts event.synopsis
      
      puts event.links.inspect
    end
    
  end
  
  
  # scan.each_host do |host|
  # 
  #   puts host.ip
  #   puts host.hostname
  #   puts host.os_name
  # 
  #   puts "\n"
  #   puts "\n"
  #   
  #   host.each_event do |event|
  #     
  #     next if event.informational?
  #     
  #     puts event.name if event.name
  #     
  #     puts event.cvss_vector
  #     
  #     #puts event.patch_publication_date.pretty if event.patch_publication_date
  #     
  #     #puts event.see_also unless event.see_also.empty?
  #     
  #     
  #     
  #     #puts event.synopsis if event.synopsis
  #     #puts event.solution if event.solution
  #     
  #   end
  #   
  #   puts "\n"
  #   puts "\n"
    
    
  # end
  
  
end
