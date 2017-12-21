# frozen_string_literal: true

require 'ruby-nessus/version'

require 'spec_helper'

describe RubyNessus do
  it 'should define a VERSION constant' do
    expect(RubyNessus).to be_const_defined('VERSION')
  end
end
