#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rubygems'
require 'nessus'

# Ruby-Nessus Example
#
# This proc is called by scan.each_host in each variation of Nessus::Parse
def print_info(host)
  puts host.ip
  puts host.hostname
  puts host.os_name
  puts host.runtime

  host.each_event do |event|
    puts "=> #{event.name}" if event.name
  end
end

Nessus::Parse.new('example_v3.nessus', :version => 2) do |scan|
  scan.each_host do |host|
    host.each_event do |event|
      puts "CPE value: #{event.cpe}"
    end
  end
end
