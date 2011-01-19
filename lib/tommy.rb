require 'yaml'
require 'tommy/base'

begin
  if File.stat("configuration.yaml") then
    configuration = YAML.dump(File.open("configuration.yaml").read)
    $TOMMY_APPLICATION = Tommy::Application.new(configuration)
  else
    configuration = { :tftp => { :addr => '127.0.0.1', :port => 6969, :verbose => TRUE } }
    $TOMMY_APPLICATION = Tommy::Application.new(configuration)
  end
rescue
end

include Tommy::Delegator
