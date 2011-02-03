Gem::Specification.new do |s|
  s.name = 'tommy'
  s.version = '0.1.2'
  s.date = '2011-02-03'

  s.description = "A TFTP Server that supports dynamic content"
  s.summary     = "A TFTP Server that supports dynamic content"

  s.authors = ["Jonathan Lassoff"]
  s.email = "jof@thejof.com"

  s.files = %w[
    lib/tommy.rb
    lib/tommy/base.rb
    lib/tommy/libtftp.rb
    tommy.gemspec
  ]
end
