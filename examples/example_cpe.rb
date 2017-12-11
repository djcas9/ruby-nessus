#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'ruby-nessus'

# Ruby-Nessus Example
#
# This proc is called by scan.each_host in each variation of Nessus::Parse
def print_info(host)
  puts host.ip
  puts host.hostname
  puts host.os_name
  puts host.runtime

  host.events.each do |event|
    puts "=> #{event.name}" if event.name
  end
end

RubyNessus::Parse.new('example_v3.nessus', version: 2) do |scan|
  scan.hosts.each do |host|
    host.events.each do |event|
      puts "CPE value: #{event.cpe}"
    end
  end
end
