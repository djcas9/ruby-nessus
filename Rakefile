require 'rubygems'
require 'rake'

require './tasks/spec.rb'
require './tasks/rdoc.rb'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "ruby-nessus"
    gem.summary = %Q{A ruby interface for nessus scan data.}
    gem.description = %Q{A ruby interface for nessus scan data.}
    gem.email = "dustin.webber@gmail.com"
    gem.homepage = "http://github.com/mephux/ruby-nessus"
    gem.authors = ["Dustin Willis Webber"]
    gem.add_development_dependency "rspec", ">= 1.2.9"
    gem.add_development_dependency "nokogiri"
    gem.add_development_dependency "chronic"
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end
