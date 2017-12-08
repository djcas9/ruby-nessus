require_relative '../spec_helper'
require_relative '../spec_fixtures/xml'

describe 'RubyNessus::Parse' do
  it 'should parse a valid v1 .nessus file' do
    expect { RubyNessus::Parse.new(Helpers::DOT_NESSUS_V1_PATH) }.not_to raise_error
  end

  it 'should parse a valid v2 .nessus file' do
    expect { RubyNessus::Parse.new(Helpers::DOT_NESSUS_V2_PATH) }.not_to raise_error
  end

  it 'should parse a valid v1 .nessus string' do
    options = { xml: Helpers::DOT_NESSUS_V1_DOC }
    expect { RubyNessus::Parse.new(nil, options) }.not_to raise_error
  end

  it 'should parse a valid v2 .nessus string' do
    options = { xml: Helpers::DOT_NESSUS_V2_DOC }
    expect { RubyNessus::Parse.new(nil, options) }.not_to raise_error
  end

  it 'should not parse other versions .nessus string' do
    options = { xml: Helpers::DOT_NESSUS_V2_DOC, version: 3 }
    expect { RubyNessus::Parse.new(nil, options) }.to raise_error('Error: Supported .Nessus Version are 1 and 2.')
  end

  it 'should not parse other versions .nessus string' do
    options = { xml: Helpers::DOT_NESSUS_VWRONG_DOC }
    expect { RubyNessus::Parse.new(nil, options).detect_version }.to raise_error('Error: Supported .Nessus Version are 1 and 2.')
  end

  it 'should return the scan' do
    options = { xml: Helpers::DOT_NESSUS_V2_DOC }
    my_nessus = RubyNessus::Parse.new(nil, options)
    expect(my_nessus.scan).to be_kind_of(RubyNessus::Version2::XML)
  end
end
