require 'yaml'
require 'logger'
require 'tommy/base'

module Tommy
  VERSION = '0.1.2'
end

$LOG = Logger.new(STDOUT)
$LOG.level = Logger::ERROR

if File.exists?("configuration.yaml") && File.stat("configuration.yaml") then
  configuration = YAML.load(File.open("configuration.yaml").read)
  unless configuration[:log_level].nil? then
    $LOG.level = configuration[:log_level]
  end
  $TOMMY_APPLICATION = Tommy::Application.new(configuration)
else
  configuration = { :addr => '127.0.0.1', :port => 6969, :verbose => TRUE }
  $TOMMY_APPLICATION = Tommy::Application.new(configuration)
end

include Tommy::Delegator
