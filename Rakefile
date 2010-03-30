require 'rubygems'
require 'rake'

require './lib/ruby-nessus/version.rb'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "ruby-nessus"
    gem.version = Nessus::VERSION
    gem.summary = "Ruby-Nessus is a ruby interface for the popular Nessus vulnerability scanner."
    gem.description = "Ruby-Nessus aims to deliver an easy yet powerful interface for interacting and manipulating Nessus scan results and configurations."
    gem.email = "dustin.webber@gmail.com"
    gem.homepage = "http://github.com/mephux/ruby-nessus"
    gem.authors = ["Dustin Willis Webber"]
    gem.add_dependency "nokogiri", ">= 1.4.0"
    gem.add_dependency "rainbow", ">= 1.0.4"
    gem.add_development_dependency "rspec", ">= 1.2.9"
    gem.add_development_dependency "yard", ">=0.2.3.5"
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

require 'spec/rake/spectask'
 
desc "Run all specifications"
Spec::Rake::SpecTask.new(:spec) do |t|
  t.libs += ['lib', 'spec']
  t.spec_opts = ['--colour', '--format', 'specdoc']
end
 
task :test => :spec
task :default => :spec

lib_dir = File.expand_path(File.join(File.dirname(__FILE__),'..','lib'))
unless $LOAD_PATH.include?(lib_dir)
  $LOAD_PATH.unshift(lib_dir)
end
 
require 'yard'
 
YARD::Rake::YardocTask.new do |t|

end
 
task :docs => :yardoc