Gem::Specification.new do |s|
  s.name = 'logstash-filter-varnishlog'
  s.version         = '1.0.1'
  s.licenses = ['Apache License (2.0)']
  s.summary = "parses varnish log"
  s.description = "The filter is a custom filter to prase vashish log data"
  s.authors = ["Warren Cahill"]
  s.email = 'warren.cahill@abc.net.au'
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.1.0", "< 3.0.0"
  s.add_development_dependency 'logstash-devutils', '~> 0'
end
