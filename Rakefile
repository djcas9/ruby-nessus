require 'rubygems'
require 'rake'

begin
  gem 'rubygems-tasks', '~> 0.2'
  require 'rubygems/tasks'

  Gem::Tasks.new
rescue LoadError => e
  warn e.message
  warn 'Run `gem install rubygems-tasks` to install Gem::Tasks.'
end

begin
  gem 'rspec', '~> 3.7'
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new
rescue LoadError
  task :spec do
    abort 'Please run `gem install rspec` to install RSpec.'
  end
end

task test: :spec
task default: :spec

begin
  gem 'yard', '~> 0.8'
  require 'yard'

  YARD::Rake::YardocTask.new
rescue LoadError
  task :yard do
    abort 'Please run `gem install yard` to install YARD.'
  end
end
task doc: :yard
