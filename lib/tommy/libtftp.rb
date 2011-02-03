#!/usr/bin/env ruby

# library for TFTP functions

require 'socket'
require 'timeout'
require 'stringio'

include Socket::Constants

class TFTPOpCode
  RRQ = 1
  WRQ = 2
  DATA = 3
  ACK = 4
  ERROR = 5
  OACK = 6
end

class TFTPException < Exception
end

class TFTPImplementation

  attr_accessor :socket, :timeout, :client, :request_callback

  def initialize(socket, timeout, client, request_callback)
    @socket = socket
    @timeout = timeout || 5
    @client = client || []
    @request_callback = request_callback || nil
  end

  def get_options(args)
    options = {}
    if not args.nil? or args.empty?
      o = args.split("\x00")
      if 1 == (o.length % 2)
        o.push("")
      end
      options = Hash[*o]
    end
  end
  
  def trace(msg)
    $LOG.debug(msg) if $LOG
  end

  def trace_received_with_options(msg, args)
    options = get_options(args)
    opts = ""
    options.each {|k,v|
     opts.insert(-1, ", %s=%s" % [k,v])
    }
    $LOG.debug("received %s%s>" % [msg, opts])
  end

  def trace_received(msg, client)
    data = msg.unpack("n")
    opcode = data[0]
    case opcode
    when TFTPOpCode::RRQ
      opcode, filename, mode, rest = msg.unpack("nZ*Z*a*")
      trace_received_with_options("RRQ <file=%s, mode=%s" % [filename, mode], rest)
    when TFTPOpCode::WRQ
      opcode, filename, mode, rest = msg.unpack("nZ*Z*a*")
      trace_received_with_options("WRQ <file=%s, mode=%s" % [filename, mode], rest)
    when TFTPOpCode::ACK
      opcode, blocknum = msg.unpack("nn")
      trace "received ACK <block=%s>" % blocknum
    when TFTPOpCode::OACK
      opcode, blocknum, rest = msg.unpack("nna*")
      trace_received_with_options("OACK <block=%d" % [blocknum], rest)
    when TFTPOpCode::DATA
      opcode, blocknum, rest = msg.unpack("nna*")
      trace "received DATA <block=%s>" % blocknum
    when TFTPOpCode::ERROR
      opcode, code, errmsg = msg.unpack("nna*")
      trace "received ERROR <code=%s, msg=%s>" % [code, errmsg]
    else
      trace "unknown opcode [%s]" % opcode
    end

  end

  # return a request object or nil
  def get_request_handler(socket = @socket)

    while TRUE
      begin
        msg, client = socket.recvfrom(65535)

        trace_received(msg, client)

        data = msg.unpack("nZ*Z*Z*Z*Z*Z*Z*Z*")
        opcode = data[0]

        if TFTPOpCode::RRQ == opcode or
            TFTPOpCode::WRQ == opcode then
          requested_filename = data[1]
          mode = data[2]
          if requested_filename.nil? or requested_filename.empty? or mode.nil? or mode.empty? then
            $LOG.warn("Request packet is missing a filename or transfer mode")
            next
          end
          case mode.downcase
          when "netascii", "octet"
          when "mail" # deprecated
          else
            $LOG.warn("Received a bad transfer mode ('%s') from [%s:%s]" % [mode, client[3], client[1]])
            next
          end

          # options
          options = Hash[*data[3..-1]]

          case opcode
          when TFTPOpCode::RRQ
            $LOG.info("Incoming read request packet for [%s] from [%s:%s]" % [requested_filename, client[3], client[1]])
          when TFTPOpCode::WRQ
            $LOG.info("Incoming write request packet for [%s] from [%s:%s]" % [requested_filename, client[3], client[1]])
          end

          ###
          begin
            # The request callback should return a nil or an IO-type object that can be written or read to (depending on the opcode)
            request_callback = @request_callback.call(@socket, client, opcode, requested_filename, mode, options)
            if request_callback.nil?
              TFTPError.UnknownError(@socket, "Denied.", client)
              next
            end

            case request_callback
            when String
              request_callback = StringIO.new(request_callback)
            when StringIO
            when File
            when IO
            else
              raise ArgumentError.new("The request_callback [%s] is of non-IOable type [%s]" % [request_callback.inspect, request_callback.class])
            end

            case opcode
            when TFTPOpCode::RRQ
              return TFTPServerRead.new(request_callback, mode, client, options)
            when TFTPOpCode::WRQ
              return TFTPServerWrite.new(request_callback, mode, client, options)
            end
          rescue Exception => e
            $LOG.debug("Caught error calling request_callback and/or handling it: #{e.inspect}")
            e.backtrace.each{|x| puts x}
            exit
          end
          ##


        else #The opcode is not a RRQ or WRQ
          $LOG.warn("Mangled packet received: %s" % msg)
        end
      end
    end
  end

  def rrq(addr, port, filename, mode, options = {})

    extra_options = ""
    opts = ""

    options.each {|k,v| 
      extra_options.insert(-1, [k.to_s,v.to_s].pack("Z*Z*")) 
      opts.insert(-1, ", %s=%s" % [k,v])
    }

    trace "sent RRQ <file=%s, mode=%s%s>" % [filename, mode, opts]
    socket.send(
                [
                 TFTPOpCode::RRQ,
                 filename,
                 mode
                ].pack("nZ*Z*") + extra_options,
                0,
                addr,
                port
                )
  end

  def wrq(addr, port, filename, mode, options = {})

    extra_options = ""
    opts = ""

    options.each {|k,v| 
      extra_options.insert(-1, [k.to_s,v.to_s].pack("Z*Z*")) 
      opts.insert(-1, ", %s=%s" % [k,v])
    }

    trace "sent WRQ <file=%s, mode=%s%s>" % [filename, mode, opts]
    socket.send(
                [
                 TFTPOpCode::WRQ,
                 filename,
                 mode
                ].pack("nZ*Z*") + extra_options,
                0,
                addr,
                port
                )
  end

  def data_read(blocknum, socket = @socket, timeout = @timeout)
    Timeout::timeout(timeout) do
      # wait for data block
      while TRUE
        trace "waiting for data: block %d" % blocknum
        msg, client = socket.recvfrom(65535)
        trace_received(msg, client)
        if client[3] == @client[3] then
          if @client[1].nil? then
            # no port exists
            @client[1] = client[1]
          elsif client[1] == @client[1]
            # matched
          else
            # bad TID
            TFTPError.BadTID(@socket, client)
            next
          end
          data = msg.unpack "nn"
          if TFTPOpCode::ERROR == data[0] then
            raise TFTPException.new("%s (%d:%s)" % [
                                                    msg.unpack("nnZ*")[2],
                                                    data[1],
                                                    TFTPError::CodeToMsg(data[1]),
                                                   ])
          elsif TFTPOpCode::DATA == data[0] and blocknum == data[1] then
            data_block = msg[4..-1]
            return data_block
          end
        end
      end
    end
  end

  def ack_read(blocknum, socket = @socket, timeout = @timeout)
    Timeout::timeout(@timeout) do
      # wait for ack
      while TRUE
        trace "waiting for ack: block %d" % blocknum
        msg, client = @socket.recvfrom(65535)
        trace_received(msg, client)
        if client[3] == @client[3] then
          if @client[1].nil? then
            # no port exists
            @client[1] = client[1]
          elsif client[1] == @client[1]
            # matched
          else
            # bad TID
            TFTPError.BadTID(@socket, client)
            next
          end
          data = msg.unpack "nn"
          if TFTPOpCode::ERROR == data[0] then
            raise TFTPException.new("%s (%d:%s)" % [
                                                    msg.unpack("nnZ*")[2],
                                                    data[1],
                                                    TFTPError::CodeToMsg(data[1]),
                                                   ])
          elsif TFTPOpCode::ACK == data[0] and blocknum == data[1] then
            return
          end
        end
      end
    end
  end

  def oack_read(blocknum, socket = @socket, timeout = @timeout)
    if 0 != blocknum
      raise Exception("bad blocknum %s" % blocknum)
    end
    Timeout::timeout(@timeout) do
      # wait for oack/ack
      while TRUE
        trace "waiting for oack: block %d" % blocknum
        msg, client = @socket.recvfrom(65535)
        trace "received from #{client}"
        trace_received(msg, client)
        if client[3] == @client[3] then
          if @client[1].nil? then
            # no port exists
            @client[1] = client[1]
          elsif client[1] == @client[1]
            # matched
          else
            # bad TID
            TFTPError.BadTID(@socket, client)
            next
          end
          data = msg.unpack "nn"
          if TFTPOpCode::ERROR == data[0] then
            raise TFTPException.new("%s (%d:%s)" % [
                                                    msg.unpack("nnZ*")[2],
                                                    data[1],
                                                    TFTPError::CodeToMsg(data[1]),
                                                   ])
          elsif TFTPOpCode::OACK == data[0] and blocknum == data[1] then
            data = msg.unpack("nnZ*Z*Z*Z*Z*Z*")
            options = Hash[*data[2..-1]]
            return options, nil
          elsif TFTPOpCode::ACK == data[0] and blocknum == data[1] then
            return {}, nil
          elsif TFTPOpCode::DATA == data[0] and ((blocknum + 1) % 65536) == data[1] then
            data_block = msg[4..-1]
            return {}, data_block
          end
        end
      end
    end
  end

  def error(errorcode, errmsg, socket = @socket, timeout = @timeout)
    trace "sent ERROR <code=%s, msg=%s>" % [errorcode, errmsg]
    socket.send(
                [
                 TFTPOpCode::ERROR, 
                 errorcode,
                 errmsg
                ].pack("nnZ*"), 0,
                @client[3], @client[1]
                )
  end

  def data_write(blocknum, data, socket = @socket, timeout = @timeout)
    trace "sent DATA <block=%d, size=%d>" % [blocknum, data.length]
    socket.send(
                [
                 TFTPOpCode::DATA,
                 blocknum,
                 data,
                ].pack("nna*"), 0,
                @client[3], @client[1]
                )
  end

  def ack_write(blocknum, socket = @socket, timeout = @timeout)
    # send an ACK
    trace "sent ACK <block=%d>" % blocknum
    ack_packet = [TFTPOpCode::ACK, blocknum].pack("nn")
    socket.send(ack_packet, 0, @client[3], @client[1])
  end

  def oack_write(blocknum, options = {}, socket = @socket, timeout = @timeout)
    # send an OACK
    oack_packet = ""
    opts = ""
    options.each {|k,v| 
      oack_packet.insert(-1, [k,v].pack("Z*Z*"))
      opts.insert(-1, ", %s=%s" % [k,v])
    }
    ack_packet = [TFTPOpCode::OACK, blocknum].pack("nn") + oack_packet
    trace "sent OACK <block=%d%s>" % [blocknum, opts]
    socket.send(ack_packet, 0, @client[3], @client[1])
  end
  
end

class TFTPError
  NOT_DEFINED = 0
  FILE_NOT_FOUND = 1
  ACCESS_VIOLATION = 2
  DISK_FULL_OR_ALLOCATION_EXCEEDED = 3
  ILLEGAL_TFTP_OPERATION = 4
  UNKNOWN_TRANSFER_ID = 5
  FILE_ALREADY_EXISTS = 6
  NO_SUCH_USER = 7
  OPTION_NEGOTIATION_REFUSED = 8

  def TFTPError.CodeToMsg(code) 
    return case (code)
           when 0 then "Not defined, see error message (if any)."
           when 1 then "File not found."
           when 2 then "Access violation."
           when 3 then "Disk full or allocation exceeded."
           when 4 then "Illegal TFTP operation."
           when 5 then "Unknown transfer ID."
           when 6 then "File already exists."
           when 7 then "No such user."
           when 8 then "Option negotiation refused."
           else "No message"
           end
  end

  def TFTPError.GenericError(socket, code, client)
    TFTPImplementation.new(socket, 5, client, nil).error(                 
                                          code,
                                          CodeToMsg(code)
                                          )
  end

  def TFTPError.UnknownError(socket, msg, client)
    TFTPImplementation.new(socket, 5, client, nil).error(                 
                                          NOT_DEFINED, 
                                          msg.to_s.empty? ? CodeToMsg(NOT_DEFINED) : msg.to_s
                                          )

  end
  def TFTPError.FileNotFound(socket, client)
    GenericError(socket, FILE_NOT_FOUND, client)
  end
  def TFTPError.AccessViolation(socket, client)
    GenericError(socket, ACCESS_VIOLATION, client)
  end

  def TFTPError.FileExists(socket, client)
    GenericError(socket, FILE_ALREADY_EXISTS, client)
  end

  def TFTPError.BadOptions(socket, client)
    GenericError(socket, OPTION_NEGOTIATION_REFUSED, client)
  end

  def TFTPError.BadTID(socket, client)
    GenericError(socket, UNKNOWN_TRANSFER_ID, client)
  end

  def TFTPError.IllegalOperation(socket, client)
    GenericError(socket, ILLEGAL_TFTP_OPERATION, client)
  end


end

# Handle an incoming read request.
class TFTPServerRead
  
  def initialize(io, mode, client, options)

    @io = io
    @mode = mode
    @client = client
    @options = options

    # set some defaults
    @retransmit = 4
    @timeout = 5 
    @blocksize = 512 

    trace "read request for [%s] from [%s:%s]" % [@io.inspect, @client[3], @client[1]]
    @socket = UDPSocket.new
    @socket.bind(0,0)

    @tftp = TFTPImplementation.new(@socket, @timeout, @client, nil)
    
  end

  def trace(msg)
    $LOG.debug(msg) if $LOG
  end

  def process

    begin

      blocksize = @blocksize

      size = @io.size
      blocknum = 0
      retransmit = @retransmit

      oack_response = {}

      @options.each do |k,v|
        if not k.empty? and not v.empty? then
          case k.downcase
          when "blksize"
            t = v.to_i
            if 8 <= t and t <= 65464 then
              blocksize = t
              oack_response[k] = v
            else
              TFTPError.BadOptions(@socket, @client)
              raise TFTPException("invalid option value; %s: %s" % [k,v])
            end
          when "timeout"
            t = v.to_i
            if 1 <= t and t <= 255 then
              timeout = t
              oack_response[k] = v
            else
              TFTPError.BadOptions(@socket, @client)
              raise TFTPException("invalid option value; %s: %s" % [k,v])
            end
          when "tsize"
            if "0" == v then
              oack_response[k] = size.to_s
            else
              TFTPError.BadOptions(@socket, @client)
              raise TFTPException("invalid option value; %s: %s" % [k,v])
            end
          end
        end
      end

      if not oack_response.empty? then
        # send an OACK
        while retransmit > 0
          begin

            trace "sending an OACK"
            @tftp.oack_write(blocknum, oack_response)
            @tftp.ack_read(blocknum)

            # data sent, ack received
            break

          rescue Timeout::Error
            $LOG.warn("Got a timeout sending an OACK response to [%s:%s]" % [client[3], client[1]])
            retransmit -= 1
          rescue Errno::ECONNREFUSED
            $LOG.warn("Connection refused from client while sending an OACK response to [%s:%s]. Spoofers?" % [client[3], client[1]])
            return
          end
        end
      end

      written = 0
      while buf = @io.read(blocksize)
        blocknum = (blocknum + 1) % 65536
        retransmit = @retransmit
        
        while retransmit > 0
          begin
            # send data

            @tftp.data_write(blocknum, buf)
            @tftp.ack_read(blocknum)

            # data sent, ack received
            break

          rescue Timeout::Error
            $LOG.warn("Got a timeout sending a data block to [%s:%s]" % [client[3], client[1]])
            retransmit -= 1
          rescue Errno::ECONNREFUSED
            $LOG.warn("Connection refused from client while sending a data block to [%s:%s]. Spoofers?" % [client[3], client[1]])
            return
          end
        end

        if 0 == retransmit then
          # timedout
          $LOG.warn("Timed out sending data to [%s:%s]" % [client[3], client[1]])
          return
        end

        written += blocksize

      end


      # FIXME / WTF
      if 0 == size % blocksize:
          # send an extra
          @tftp.data_write((blocknum + 1) % 65536, "")
      end
      #

      trace "completed file read"

    rescue TFTPException => e
      trace "read: caught TFTP exception: " + e.to_s
    rescue Exception => e
      trace "read: caught exception: " + e.to_s + "\n" + e.backtrace.join("\n")
      TFTPError.UnknownError(@socket, e, @client)
    end

  end

end

# Handle an incoming write request
class TFTPServerWrite

  def initialize(io, mode, client, options)

    @io = io
    @mode = mode
    @client = client
    @options = options

    # set some defaults
    @retransmit = 4
    @timeout = 5 
    @blocksize = 512 

    trace "write request for [%s] from [%s:%s]" % [@io.inspect, @client[3], @client[1]]
    @socket = UDPSocket.new
    @socket.bind(0,0)

    @tftp = TFTPImplementation.new(@socket, @timeout, @client, nil)

  end

  def trace(msg)
    $LOG.debug(msg) if $LOG
  end
  
  def process

    begin

      blocksize = @blocksize

      size = 0
      written = 0
      blocknum = 0
      retransmit = @retransmit

      oack_response = {}

      @options.each do |k,v|
        if not k.empty? and not v.empty? then
          case k.downcase
          when "blksize"
            t = v.to_i
            if 8 <= t and t <= 65464 then
              blocksize = t
              oack_response[k] = v
            end
          when "timeout"
            t = v.to_i
            if 1 <= t and t <= 255 then
              @tftp.timeout = t
              oack_response[k] = v
            end
          when "tsize"
            oack_response[k] = v
          end
        end
      end

      file = nil

      keep_writing = TRUE
      first = TRUE
      while keep_writing

        retransmit = @retransmit
        data_block = nil
        while retransmit > 0
          begin

            if (not oack_response.empty?) and first then
              @tftp.oack_write(blocknum, oack_response)
            else
              @tftp.ack_write(blocknum)
            end

            data_block = @tftp.data_read((blocknum + 1) % 65536)

            # ack sent, data received
            break

          rescue Timeout::Error
            $LOG.warn("Got a timeout reading a data block from [%s:%s]" % [client[3], client[1]])
            retransmit -= 1
          rescue Errno::ECONNREFUSED
            $LOG.warn("Connection refused from [%s:%s] while reading data blocks. Spoofers?" % [client[3], client[1]])
            return
          end
        end

        first = FALSE

        if 0 == retransmit then
          # timedout
          $LOG.warn("Timed out reading data from [%s:%s]" % [client[3], client[1]])
          return
        end

        @io.write(data_block)
        @io.flush

        # block written
        blocknum = (blocknum + 1) % 65536

        if data_block.length < blocksize then
          io.close
          keep_writing = FALSE
        end

      end

      # final ack
      @tftp.ack_write(blocknum)

    rescue TFTPException => e
      trace "write: caught TFTP exception: " + e.to_s
    rescue Exception => e
      trace "write: caught exception: " + e.to_s + "\n" + e.backtrace.join("\n")
      TFTPError.UnknownError(@socket, e, @client)
    end

  end

end

class TFTPServer

  def initialize(host, port, request_callback)
    $LOG.info("TFTP Server starting...")
    @host = host || '0.0.0.0'
    @port = port || 6969
    @request_callback = request_callback

    @socket = UDPSocket.new
    @socket.bind @host, @port

    @tftp = TFTPImplementation.new(@socket, 5, [], request_callback)
    @tftp.request_callback = request_callback
  end

  def trace(msg)
    $LOG.debug(msg) if $LOG
  end

  def process_request(request)
    begin
      trace "processing request: " + request.to_s
      request.process()
    rescue Exception => e
      trace "Caught exception: %s\n%s" % [ e.message , e.backtrace ]
    end
    Thread.exit
  end

  def listen
    keep_looping = TRUE
    threads = []
    while keep_looping 
      begin
        request = @tftp.get_request_handler

        if not request.nil? then
          threads << Thread.new { self.process_request(request) }
        end
      rescue Interrupt
        threads.each {|t| 
          if t.alive? then 
            trace "waiting on thread: %s" % t.to_s
            t.join 
          end 
        }
        keep_looping = FALSE
      end
    end
  end

end
