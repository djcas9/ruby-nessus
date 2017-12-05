module Helpers
  DOT_NESSUS_V1_PATH = File.join(File.dirname(__FILE__), 'example_v1.nessus')
  DOT_NESSUS_V2_PATH = File.join(File.dirname(__FILE__), 'example_v2.nessus')

  DOT_NESSUS_V1_DOC = File.read(DOT_NESSUS_V1_PATH)
  DOT_NESSUS_V2_DOC = File.read(DOT_NESSUS_V2_PATH)

  DOT_NESSUS_V1 = Nokogiri::XML.parse(DOT_NESSUS_V1_DOC)
  DOT_NESSUS_V2 = Nokogiri::XML.parse(DOT_NESSUS_V2_DOC)
end
