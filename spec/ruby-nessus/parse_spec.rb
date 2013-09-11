require_relative '../spec_helper'
require_relative '../helpers/xml'

describe 'Nessus::Parse' do
  it 'should parse a valid v1 .nessus file' do
    Nessus::Parse.new(Helpers::DOT_NESSUS_V1_DOC).should_not raise_error
  end

  it 'should parse a valid v2 .nessus file' do
    Nessus::Parse.new(Helpers::DOT_NESSUS_V2_DOC).should_not raise_error
  end

  it 'should parse a valid v1 .nessus string' do
    options = { :xml => Helpers::DOT_NESSUS_V1_DOC }
    Nessus::Parse.new(nil, options).should_not raise_error
  end

  it 'should parse a valid v2 .nessus string' do
    options = { :xml => Helpers::DOT_NESSUS_V2_DOC }
    Nessus::Parse.new(nil, options).should_not raise_error
  end
end
