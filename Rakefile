require 'rubygems'
require 'rake'

require './tasks/spec.rb'
require './tasks/rdoc.rb'

begin
  
  require 'yard'
  YARD::Rake::YardocTask.new do |t|
    # Build Yardoc
  end
  
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "ruby-nessus"
    gem.summary = "Ruby-Nessus is a ruby interface for the popular Nessus vulnerability scanner."
    gem.description = "Ruby-Nessus aims to deliver an easy yet powerful interface for interacting and manipulating Nessus scan results and configurations."
    gem.email = "dustin.webber@gmail.com"
    gem.homepage = "http://github.com/mephux/ruby-nessus"
    gem.authors = ["Dustin Willis Webber"]
    gem.add_dependency "nokogiri", ">= 1.4.0"
    gem.add_development_dependency "rspec", ">= 1.2.9"
    gem.add_development_dependency "yard", ">=0.2.3.5"
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end