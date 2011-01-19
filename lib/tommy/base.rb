require 'tommy/libtftp'

VERSION = '0.1a'

module Tommy
  class Application
    def initialize(configuration)
      configuration = configuration[:tftp]

      unless File.directory?(configuration[:directory])
        raise ArgumentError.new("#{configuration[:directory]} is not a directory") 
      end

      server = TFTPServer.new(configuration[:addr], configuration[:port], configuration[:verbose], request_callback, io_callback)
      server.listen
    end

    def self.get(*pathspec, &block)
      p pathspec
      p block
    end
  end

  module Delegator
    def self.delegate(*methods)
      methods.each do |method|
        eval <<-RUBY, binding, "(__Tommy::Delegator__)", 1
          def #{method}(*args, &block)
            ::Tommy::Application.send(#{method.inspect}, *args, &block)
          end
          private #{method.inspect}
        RUBY
      end

      delegate :get
    end
  end
end
