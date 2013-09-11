module Helpers
  v1 = File.join(File.dirname(__FILE__),'example_v1.nessus')
  v2 = File.join(File.dirname(__FILE__),'example_v2.nessus')

  DOT_NESSUS_V1_DOC = File.read(v1)
  DOT_NESSUS_V2_DOC = File.read(v2)

  DOT_NESSUS_V1 = Nokogiri::XML.parse(DOT_NESSUS_V1_DOC)
  DOT_NESSUS_V2 = Nokogiri::XML.parse(DOT_NESSUS_V2_DOC)
end
