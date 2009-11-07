require '../lib/ruby-nessus'
require 'pp'

Nessus::XML.new("1test.nessus") do |scan|

  #test
  #puts scan.ports

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

  pp scan.hosts.join(', ')
  
  puts "Hosts:"
  scan.hosts do |host|
    puts host
  end
  
  #puts scan.severities
  
  # plugins
  # scan.plugins.each do |p|
  #   puts p
  #   sleep 1
  # end
  
end
  
  