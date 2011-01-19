#!/usr/bin/env ruby

require 'erb'
require 'stringio'

class TFTPServerInstance
  attr_accessor :directory, :write_enable

  def initialize(configuration)
    configuration = configuration[:tftp]

    unless File.directory?(configuration[:directory])
      raise ArgumentError.new("#{configuration[:directory]} is not a directory") 
    end

    server = TFTPServer.new(configuration[:addr], configuration[:port], configuration[:verbose], request_callback, io_callback)
    server.listen
  end

  def render_request(filename, client)
    begin
      possible_template = File.dirname(__FILE__)+File::SEPARATOR+'..'+File::SEPARATOR+'views'+File::SEPARATOR+'tftp'+File::SEPARATOR+filename+'.erb'
      stat = File.stat(possible_template)
      if stat then

        ####
        # This needs to be in inventory.rb
        provisioning_url = '/provision'
        service_tag = 'AAAABBBB'
        hostname = 'foobarbaz'
        root_password_hash = ROOT_PASSWORD_HASH
        ####

        template = File.open(possible_template, 'r').read
        erb_template = ERB.new(template)
        rendered_response = erb_template.result(binding)
        return rendered_response
      end
    rescue Exception => e
      STDERR.puts "Error rendering request response. Filename: #{filename}. Exception: #{e.inspect}"
      return nil
    end
  end

  private
  def request_callback
    # define an appropriate callback
    request_callback = Proc.new do |socket, client, opcode, filename, mode, options|

      case self.render_request(filename, client)
      when NilClass # Plain file server
          # validate absolute or relative paths
        if ( filename[0] == '/' or filename.match(/\.\.[\/\\]/) ) then
          TFTPError.AccessViolation(socket, client)
          next FALSE
        end
        if not File.exists?(filename) then
          TFTPError.FileNotFound(@socket, @client)
          next FALSE
        elsif not File.file?(filename) then
          TFTPError.FileNotFound(@socket, @client)
          next FALSE
        elsif not File.readable?(filename) then
          TFTPError.AccessViolation(@socket, @client)
          next FALSE
        end
        if  opcode == TFTPOpCode::WRQ and not write then
          TFTPError.AccessViolation(socket, client)
          next FALSE
        end
        next TRUE
      when String # Rendered request
        next TRUE
      end
    end
  end

  def io_callback
    io_callback = Proc.new do |socket, client, opcode, filename, mode, options|

      case opcode
      when TFTPOpCode::RRQ
        rendered_request = self.render_request(filename, client)
        if rendered_request.nil? then
          io = File.open(@directory+File::SEPARATOR+filename, 'r')
        else
          io = StringIO.new(rendered_request)
        end
      when TFTPOpCode::WRQ
        io = File.open(@directory+File::SEPARATOR+filename, 'w+')
      end

      io
    end
  end

end
