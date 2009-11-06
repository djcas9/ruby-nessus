require '../lib/ruby-nessus'
require 'pp'

Nessus::XML.new("test.nessus") do |s|
  puts s.node_count
end
  
  