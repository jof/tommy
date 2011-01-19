require 'rake/clean'
require 'rake/testtask'
require 'fileutils'
require 'date'

task :default => :test
task :spec => :test

def source_version
  line = File.read('lib/sinatra/base.rb')[/^\s*VERSION = .*/]
  line.match(/.*VERSION = '(.*)'/)[1]
end

# SPECS ===============================================================
task :test do
  ENV['LANG'] = 'C'
  ENV.delete 'LC_CTYPE'
end

Rake::TestTask.new(:test) do |t|
  t.test_files = FileList['test/*_test.rb']
  t.ruby_opts = ['-rubygems'] if defined? Gem
  t.ruby_opts << '-I.'
end
# Rcov ================================================================
namespace :test do
  desc 'Mesures test coverage'
  task :coverage do
    rm_f "coverage"
    rcov = "rcov --text-summary -Ilib"
    system("#{rcov} --no-html --no-color test/*_test.rb")
  end
end

# PACKAGING ============================================================

if defined?(Gem)
  # Load the gemspec using the same limitations as github
  def spec
    require 'rubygems' unless defined? Gem::Specification
    @spec ||= eval(File.read('tommy.gemspec'))
  end

  def package(ext='')
    "pkg/tommy-#{spec.version}" + ext
  end

  desc 'Build packages'
  task :package => %w[.gem .tar.gz].map {|e| package(e)}

  desc 'Build and install as local gem'
  task :install => package('.gem') do
    sh "gem install #{package('.gem')}"
  end

  directory 'pkg/'
  CLOBBER.include('pkg')

  file package('.gem') => %w[pkg/ tommy.gemspec] + spec.files do |f|
    sh "gem build tommy.gemspec"
    mv File.basename(f.name), f.name
  end

  file package('.tar.gz') => %w[pkg/] + spec.files do |f|
    sh <<-SH
      git archive \
        --prefix=tommy-#{source_version}/ \
        --format=tar \
        HEAD | gzip > #{f.name}
    SH
  end

  task 'tommy.gemspec' => FileList['{lib,test,compat}/**','Rakefile','*.rdoc'] do |f|
    # read spec file and split out manifest section
    spec = File.read(f.name)
    head, manifest, tail = spec.split("  # = MANIFEST =\n")
    # replace version and date
    head.sub!(/\.version = '.*'/, ".version = '#{source_version}'")
    head.sub!(/\.date = '.*'/, ".date = '#{Date.today.to_s}'")
    # determine file list from git ls-files
    files = `git ls-files`.
      split("\n").
      sort.
      reject{ |file| file =~ /^\./ }.
      reject { |file| file =~ /^doc/ }.
      map{ |file| "    #{file}" }.
      join("\n")
    # piece file back together and write...
    manifest = "  s.files = %w[\n#{files}\n  ]\n"
    spec = [head,manifest,tail].join("  # = MANIFEST =\n")
    File.open(f.name, 'w') { |io| io.write(spec) }
    puts "updated #{f.name}"
  end

  task 'release' => package('.gem') do
    sh <<-SH
      gem install #{package('.gem')} --local &&
      gem push #{package('.gem')}  &&
      git add tommy.gemspec &&
      git commit --allow-empty -m '#{source_version} release'  &&
      git tag -s #{source_version} -m '#{source_version} release'  &&
      git push && (git push tommy || true) &&
      git push --tags && (git push tommy --tags || true)
    SH
  end
end
