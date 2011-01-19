Gem::Specification.new do |s|
  s.specification_version = 2 if s.respond_to? :specification_version=
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=

  s.name = 'tommy'
  s.version = '0.1a'
  s.date = '2011-01-19'

  s.description = "A TFTP Server that supports dynamic content"
  s.summary     = "A TFTP Server that supports dynamic content"

  s.authors = ["Jonathan Lassoff"]
  s.email = "jof@thejof.com"

  # = MANIFEST =
  s.files = %w[
    Rakefile
    lib/tommy.rb
    lib/tommy/libtftp.rb
    lib/tommy/base.rb
    tommy.gemspec
  ]
  # = MANIFEST =

  s.test_files = s.files.select {|path| path =~ /^test\/.*_test.rb/}

  s.extra_rdoc_files = %w[]

  s.has_rdoc = true
  s.require_paths = %w[lib]
end
