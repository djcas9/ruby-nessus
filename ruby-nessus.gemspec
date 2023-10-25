# frozen_string_literal: true

$LOAD_PATH.push File.expand_path('lib', __dir__)

Gem::Specification.new do |gem|
  gem.name        = 'ruby-nessus'
  gem.version     = '2.0.2'
  gem.summary     = 'Ruby-Nessus is a ruby interface for the popular Nessus vulnerability scanner.'
  gem.description = 'Ruby-Nessus aims to deliver an easy yet powerful interface for interacting and manipulating Nessus scan results and configurations.'
  gem.licenses    = ['MIT']
  gem.authors     = ['Dustin Willis Webber', 'Florian Wininger']
  gem.email       = 'dustin.webber@gmail.com'
  gem.homepage    = 'https://github.com/Cyberwatch/ruby-nessus'

  gem.files            = `git ls-files`.split("\n")
  gem.executables      = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  gem.test_files       = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.require_paths = ['lib']
  gem.required_ruby_version = '>= 2.3'

  gem.add_dependency 'nokogiri', '>= 1.10.10'
  gem.add_dependency 'rainbow', '>= 3.0'

  gem.add_development_dependency 'rspec', '~> 3.7'
  gem.add_development_dependency 'rubocop', '~> 0.51'
  gem.add_development_dependency 'rubygems-tasks', '~> 0.1'
  gem.add_development_dependency 'yard', '~> 0.9.11'
end
