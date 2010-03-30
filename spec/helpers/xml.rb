module Helpers
  v1 = File.join(File.dirname(__FILE__),'example_v1.nessus')
  v2 = File.join(File.dirname(__FILE__),'example_v2.nessus')
  DOT_NESSUS_V1 = Nokogiri::XML.parse(File.open(v1).read)
  DOT_NESSUS_V2 = Nokogiri::XML.parse(File.open(v2).read)
end