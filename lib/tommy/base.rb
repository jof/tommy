require 'erb'
require 'tommy/libtftp'

module Tommy
  class Application

    attr_accessor :routes, :file_directory, :template_directory

    def initialize(configuration)
      @app_file = File.join(ENV['PWD'], caller.last.split(':').first)
      @file_directory = configuration[:file_directory] || File.join(File.dirname(@app_file), 'public')
      @template_directory = configuration[:template_directory] || File.join(File.dirname(@app_file), 'views')
      self.routes = []

      unless File.directory?(@file_directory)
        $LOG.error("#{@file_directory} is not a directory.")
        raise ArgumentError.new("#{@file_directory} is not a directory") 
      end

      # Determine now to handle a read or write request
      request_callback = Proc.new do |socket, client, opcode, requested_filename, mode, options|
        return_value = nil

        # Is this a RRQ and is there a route for this path?
        if opcode == TFTPOpCode::RRQ then
          @routes.each do |route_regex, captures, block|
            $LOG.debug("checking #{route_regex.inspect}, #{captures.inspect}, #{block.inspect}")
            if (matches = route_regex.match(requested_filename)) then # There's a route defined for this path
                if (matches.length > 1) then # There is capture data to save
                  matches = matches.to_a[1..-1] # MatchData captures to Array

                  if (captures && captures.length > 0) then
                    params = captures.zip(matches) # Save a list of tuples ([:param_name, match])
                    # Save a hash of { :param_name => match }
                    hash = {}
                    params.each { |param, match| hash[param] = match }
                    params = hash
                  else # No named captures listed, but captures found. Likely a regex-based route
                    params = { :captures => matches }
                  end


                  $LOG.info("GET %s from [%s:%s]" % [requested_filename, client[3], client[1]])
                  return_value = block.call(params)
                  break # First match wins
                else
                  $LOG.info("GET %s from [%s:%s]" % [requested_filename, client[3], client[1]])
                  return_value = block.call
                  break # First match wins
                end
            end
          end
        # If not, act like a regular static file server
        else
          # Check for .. and . in path components
          path_components = requested_filename.split(File::SEPARATOR)
          if (path_components.include?('.') || path_components.include?('..')) then
            return_value = nil
          end

          case opcode
          when TFTPOpCode::RRQ
            $LOG.info("GET %s from [%s:%s]" % [requested_filename, client[3], client[1]])
            return_value = File.open(File.join(@file_directory, requested_filename), 'r')
          when TFTPOpCode::WRQ
            $LOG.info("PUT %s from [%s:%s]" % [requested_filename, client[3], client[1]])
            return_value = File.open(File.join(@file_directory, requested_filename), 'w+')
          end

        end
        
        if return_value == nil then # No other value was set so far
          case opcode
          when TFTPOpCode::RRQ
            $LOG.info("Denied GET %s from [%s:%s]" % [requested_filename, client[3], client[1]])
          when TFTPOpCode::WRQ
            $LOG.info("Denied PUT %s from [%s:%s]" % [requested_filename, client[3], client[1]])
          end
        end

        next return_value
      end # request_callback

      server_thread = Thread.new do
        server = TFTPServer.new(configuration[:addr], configuration[:port], request_callback)
        server.listen
      end
      at_exit do 
        server_thread.join
      end
    end

    def self.tftp_get(*pathspec, &block)
      route_spec = pathspec.first

      case route_spec
      when String
        route_spec_parts = route_spec.split('/')
        captures = []
        route_regex_parts = route_spec_parts.map do |x|
          matches = x.match(/:[A-Za-z0-9\-_]+/)
          param = matches[0].to_sym if matches
          captures << param if param
          if param then
            return "([a-zA-Z0-9\\-_]+)"
          else
            return x
          end
        end 
        route_regex = Regexp.new(route_regex_parts.join('/'))
      when Regexp
        route_regex = route_spec
      end

      route = [ route_regex, captures, block ]
      $TOMMY_APPLICATION.routes = $TOMMY_APPLICATION.routes << route
    end

    def self.erb(template_name, a_binding)
      template_file_name = File.join($TOMMY_APPLICATION.template_directory, template_name.to_s+".erb")
      begin
     
        template = File.open(template_file_name, 'r').read
        eruby = ERB.new(template)
        return eruby.result(a_binding)
      rescue Errno::ENOENT => e
        $LOG.error("Coult not find template #{template_name} at #{template_file_name}")
      end
    end

    def self.erubis(template_name, a_binding)
      template_file_name = File.join($TOMMY_APPLICATION.template_directory, template_name.to_s+".erb")
      begin
        template = File.open(template_file_name, 'r').read
        eruby = Erubis::Eruby.new(template)
        return eruby.result(a_binding)
      rescue Errno::ENOENT => e
        $LOG.error("Could not find template #{template_name} at #{template_file_name}")
      end
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
    delegate :tftp_get
    delegate :erb, :erubis
  end
end
