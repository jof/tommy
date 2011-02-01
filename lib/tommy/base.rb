require 'tommy/libtftp'

module Tommy
  class Application

    attr_accessor :routes

    def initialize(configuration)
      @app_file = File.join(ENV['PWD'], caller.last.split(':').first)
      @directory = configuration[:directory] || File.join(File.dirname(@app_file), 'public')
      self.routes = []

      unless File.directory?(@directory)
        $LOG.error("#{@directory} is not a directory.")
        raise ArgumentError.new("#{@directory} is not a directory") 
      end

      # Determine now to handle a read or write request
      request_callback = Proc.new do |socket, client, opcode, requested_filename, mode, options|
        #$LOG.debug("In the request callback. Called with: #{socket} #{client} #{opcode} #{requested_filename} #{mode} #{options}")

        # Is this a RRQ and is there a route for this path?
        if opcode == TFTPOpCode::RRQ then
          @routes.each do |route_regex, captures, block|
            $LOG.debug("checking #{route_regex.inspect}, #{captures.inspect}, #{block.inspect}")
            if (matches = route_regex.match(requested_filename)) then # There's a route defined for this path
                if (matches.length > 1) then # There is capture data to save
                  matches = matches.to_a[1..-1] # MatchData captures to Array
                  params = captures.zip(matches) # Save a list of tuples ([:param_name, match])

                  hash = {}
                  params.each { |param, match| hash[param] = match }
                  params = hash

                  return block.call(params)
                else
                  return block.call
                end
            end
          end
        # If not, act like a regular static file server
        else
          # Check for .. and . in path components
          path_components = requested_filename.split(File::SEPARATOR)
          if (path_components.include?('.') || path_components.include?('..')) then
            return nil
          end

          case opcode
          when TFTPOpCode::RRQ
            return File.open(File.join(@directory, requested_filename), 'r')
          when TFTPOpCode::WRQ
            return File.open(File.join(@directory, requested_filename), 'w+')
          end

        end
        
      end # request_callback

      server_thread = Thread.new do
        server = TFTPServer.new(configuration[:addr], configuration[:port], request_callback)
        server.listen
      end
      at_exit do 
        server_thread.join
      end
    end

    def self.get(*pathspec, &block)
      route_spec = pathspec.first
      route_spec_parts = route_spec.split('/')

      captures = []
      route_regex_parts = route_spec_parts.map do |x|
        matches = x.match(/:[A-Za-z0-9\-_]+/)
        param = matches[0].to_sym if matches
        captures << param if param
        if param then
          "([a-zA-Z0-9\\-_]+)"
        else
          x
        end
      end 

      route_regex = Regexp.new(route_regex_parts.join('/'))
      route = [ route_regex, captures, block ]
      $TOMMY_APPLICATION.routes = $TOMMY_APPLICATION.routes << route
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
    end
    delegate :get
  end
end
