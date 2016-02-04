require 'socket'
require 'thread'
require 'csv'
require 'set'
require 'time'
require 'base64'

Thread::abort_on_exception = true

class Packet
    # ~~!!!!~~~!!! IMPORTANT!!! !!!~~~!!!!~~
    #     every time you define a new type of packet, you need to
    #     add it here
    @@validHeaders = ["HELLO",
                      "LINKSTATE",
                      "SNDMSG",
                      "PING",
                      "TRACEROUTE",
                      "FTP",
                      "BLACKHOLE",
                      "FAILURE",
                      "FRAGMENT",
                      "CLOCKSYNC"].to_set

    def initialize(typ, srcHn, dstHn, seqNo)
        @type = typ
        @srcHostname = srcHn
        @dstHostname = dstHn
        @seqNum = seqNo
        @ack = false

        @payload = Array.new

        Thread::abort_on_exception = true
    end

    def self.fromString(line)
        ret = Packet.new("", "", "", -500)
        arr = line.split

        ret.type = arr[0]
        if !(@@validHeaders.include?(ret.type))
            return nil
        end

        ret.srcHostname = arr[1]
        ret.dstHostname = arr[2]
        ret.seqNum = arr[3].to_i
        ret.ack = (arr[4] == "true")

        for i in 5 ... arr.size
            ret.payload[i - 5] = arr[i]
        end

        return ret
    end

    def to_s()
        header = @type + " " + @srcHostname + " " + @dstHostname + " " + \
                     @seqNum.to_s + " " + @ack.to_s + " "
        str = header + @payload.join(" ")
        str = str + "\n"
        return str
    end

    attr_accessor :type, :srcHostname, :dstHostname, :seqNum, :ack, :payload
end

class Protocol
    def initialize(targetNode)
        # [node]: node to run this protocol on
        @node = targetNode

        # [lock]: mutex for this class, because multithreading
        @lock = Mutex.new

        # [seqNum]: current sequence number
        @seqNum = 1

        # [seqsBack]: sequence numbers we've received back, for PING
        @seqsBack = Set.new

        # [pingTimeout]: # of seconds to wait before returning a timeout error (not just
        #                for ping, but for all types of instructions)
        # TODO: read from config file
        @pingTimeout = 3

        # [updateInterval]: update interval for link state protocol
        # TODO: read from config file
        @updateInterval = 5

        # [maxPayloadSize]: max payload size in characters
        # TODO: read from config file
        @maxPayloadSize = 10

        # where we keep the fragments that come in
        @fragments = Hash.new

        # keeps track of the time
        @currentTime = 0.0

        # lock for the time
        @timeLock = Mutex.new

        # clocksyncs we have received back
        @clocksyncs = Hash.new

        Thread::abort_on_exception = true
    end

    def execute()
        # first, issue a hello message to find out which nodes are alive/active
        sayHello()
        @node.populateValidWeights()
        sendLinkStatePacket()

        # then, launch the various threads governing the protocol
        Thread::abort_on_exception = true
        Thread.new { linkStateThread() }
        Thread.new { messageReceivingThread() }
        Thread.new { timeThread() }
        inputThread()
    end





    # -------------------------------------------------------------------------
    #  three threads of the protocol
    # -------------------------------------------------------------------------

    # link state update thread
    def linkStateThread()
        while 1
            sleep(@updateInterval)
            updateNode()
        end
    end

    def timeThread()
      @currentTime = Time.now.to_f
      while 1
        sleep(0.01)
        @timeLock.synchronize {
          @currentTime = @currentTime + 0.01
        }
      end
    end

    def getLocalTime()
      @timeLock.synchronize {
        return @currentTime
      }
    end

    def setLocalTime(timeIn)
      @timeLock.synchronize {
        @currentTime = timeIn
      }
    end

    def updateNode()
        @node.lock.synchronize {
            sayHello() #important if a node comes up after the initial round of hellos
            @node.populateValidWeights()
            sendLinkStatePacket()
            @node.updateRoutingTable()
        }
    end

    # message receiving thread
    def messageReceivingThread()
        server = TCPserver.new @node.port.to_i

        while 1
            Thread.start(server.accept) do |client|
                while line = client.gets
                    p = Packet.fromString(line)
                    if (p == nil)
                        puts "ERROR: invalid packet received! : #{line}"
                    end

                    STDOUT.flush

                    if p.type == "HELLO"
                        onReceive_HELLO(p)
                    elsif p.type == "LINKSTATE"
                        onReceive_LINKSTATE(p)
                    elsif p.type == "SNDMSG"
                        onReceive_SNDMSG(p)
                    elsif p.type == "PING"
                        onReceive_PING(p)
                    elsif p.type == "FAILURE"
                        onReceive_FAILURE(p)
                    elsif p.type == "TRACEROUTE"
                        onReceive_TRACEROUTE(p)
                    elsif p.type == "FTP"
                        onReceive_FTP(p)
                    elsif p.type == "BLACKHOLE"
                        onReceive_BLACKHOLE(p)
                    elsif p.type == "FRAGMENT"
                        onReceive_FRAGMENT(p)
                    elsif p.type == "CLOCKSYNC"
                        onReceive_CLOCKSYNC(p)
                    end
                end
            end
            sleep(0.01)
        end
    end

    # user input thread (stdin)
    def inputThread()
        while 1
            inputStdin = $stdin.gets.chomp
            input = inputStdin.split()

            if input[0] == "PRINT"
                onInput_PRINT(input)
            elsif input[0] == "SNDMSG"
                onInput_SNDMSG(input)
            elsif input[0] == "FORCEUPDATE"
                updateNode()
            elsif input[0] == "PING"
                onInput_PING(input)
            elsif input[0] == "TRACEROUTE"
                onInput_TRACEROUTE(input)
            elsif input[0] == "FTP"
                onInput_FTP(input)
            elsif input[0] == "BLACKHOLE"
                onInput_BLACKHOLE(input)
            elsif input[0] == "REMOVEHOLE"
                onInput_REMOVEHOLE(input)
            elsif input[0] == "CLOCKSYNC"
                onInput_CLOCKSYNC(input)
            end
        end
        sleep(0.01)
    end





    # -------------------------------------------------------------------------
    # specific message-receiving handlers
    # -------------------------------------------------------------------------

    # HELLO
    def onReceive_HELLO(packet)
        ip = packet.payload[0]

        @node.lock.synchronize{
            @node.hello.add(ip)
        }

        if packet.payload[1] == "forward"
            outgoingInterface = @node.neighborToInterface[ip]

            # send ACK response back
            packet = Packet.new("HELLO", @node.hostname, @node.ipToHostname[ip], @seqNum)
            packet.ack = true
            packet.payload = [outgoingInterface]
            sendPacket(packet, ip)
        end
    end

    # LINKSTATE
    def onReceive_LINKSTATE(packet)
        # break LINKSTATE packet down into its constituent parts
        w = Weight.new
        w.srcHostname = packet.payload[0]
        w.srcIp = packet.payload[1]
        w.dstHostname = packet.payload[2]
        w.dstIp = packet.payload[3]
        w.cost = packet.payload[4]
        port = packet.payload[5].to_i
        seqN = packet.seqNum

        @node.lock.synchronize {
            # if we've already encountered this edge, we need to check if the sequence
            # number is higher than the last one we've seen; if it isn't, we don't update
            if (@node.validWeights.ipMap[w.srcIp][w.dstIp])
                if (@node.sequenceNumPath[w.srcIp][w.dstIp])
                    if (seqN <= @node.sequenceNumPath[w.srcIp][w.dstIp])
                        next
                    end
                end
            end

            # update all necessary information
            @node.validWeights.push(w)
            @node.sequenceNumPath[w.srcIp][w.dstIp] = seqN
            @node.sequenceNumPath[w.dstIp][w.srcIp] = seqN
            @node.ipToHostname[w.srcIp] = w.srcHostname
            @node.ipToHostname[w.dstIp] = w.dstHostname
            @node.hostnameToPort[w.srcHostname] = port

            # flood neighbors
            flood(packet)
        }
    end

    # SNDMSG
    def onReceive_SNDMSG(packet)
        # forward packet as appropriate
        retval = forwardPacket(packet)

        if (retval == 1)
            # if we're the target, output the message
            srcHostname = packet.srcHostname
            message = packet.payload.join(" ")
            puts "SENDMSG: " + srcHostname + " --> " + message
        elsif (retval == -1)
            # if we failed, send a failure packet back
            sendFailurePacket(packet)
        end
    end

    # PING (forward + ack)
    def onReceive_PING(packet)
        retval = forwardPacket(packet)

        if (retval == 1)
            # different behavior for initial vs. ack
            if (!packet.ack)
                # swap source/destination hostname
                # and send the packet back
                tmp = packet.srcHostname
                packet.srcHostname = packet.dstHostname
                packet.dstHostname = tmp
                packet.ack = true
                forwardPacket(packet)
            else
                # output the round trip time since the PING packet with this
                # sequence number was sent out
                time = ((getLocalTime() - packet.payload[1].to_f) * 1000).round
                puts "#{packet.payload[0]} #{@node.hostname} #{time}ms"

                # record sequence number into set
                @lock.synchronize {
                    @seqsBack.add(packet.seqNum)
                }
            end
        end

        # (unlike other packet types, we don't handle the failure case here because we
        #  adhere to the ping timeout)
    end

    # TRACEROUTE (forward + ack)
    def onReceive_TRACEROUTE(packet)
        retval = 0

        # if it's an ACK, just forward it back
        if (packet.ack)
            retval = forwardPacket(packet)

            # if we're back at the source...
            if (retval == 1)
                # get round trip time
                time = ((getLocalTime() - packet.payload[1].to_f) * 1000).round

                # get original hopcount
                origHopcount = packet.payload[2].to_i

                # print output
                puts "#{origHopcount} #{packet.srcHostname} #{time}ms"

                # if the ACK didn't come from the destination, increment hopcount, and
                # run a forward pass again
                if (packet.srcHostname != packet.payload[3])
                    packet.srcHostname = @node.hostname
                    packet.dstHostname = packet.payload[3]
                    packet.ack = false
                    packet.payload[0] = origHopcount + 1
                    packet.payload[1] = getLocalTime()
                    packet.payload[2] = origHopcount + 1

                    retval = forwardPacket(packet)
                end
            end
        else
            # get hopcount and decrement
            hopcount = packet.payload[0].to_i
            hopcount = hopcount - 1
            packet.payload[0] = hopcount

            if (hopcount == 0)
                # if it's reached 0, send back an ack
                tmp = packet.srcHostname
                packet.srcHostname = @node.hostname
                packet.dstHostname = tmp
                packet.ack = true
                retval = forwardPacket(packet)
            else
                # if not, forward
                retval = forwardPacket(packet)
            end
        end

        # if we had a failure at any point, send a failure packet back
        if (retval == -1)
            sendFailurePacket(packet)
        end
    end

    # FTP (forward + ack)
    def onReceive_FTP(packet)
        # forward packet as appropriate
        retval = forwardPacket(packet)

        if (!packet.ack)
            # forward pass
            dir = packet.payload[0]
            fname = packet.payload[1]
            origTime = packet.payload[2]

            filepath = dir + "/" + fname
            failure = false
            bytesTransferred = 0

            if (retval == 1)
                # if we're the target, recreate the byte array and output the file
                fileStr = packet.payload[3 ... packet.payload.size].join(" ")
                fileStr = [fileStr].pack('H*')

                File.open(filepath, 'wb') { |f|
                    begin
                        f.write(fileStr)
                    rescue
                        failure = true
                    end
                }

                # get # of bytes transferred by reading the size of the file
                bytesTransferred = File.size(filepath)

                if (!failure)
                    puts "FTP: #{packet.srcHostname} => #{filepath}"
                end
            elsif (retval == -1)
                failure = true
                bytesTransferred = 0
            end

            if (failure)
                puts "FTP ERROR: #{packet.srcHostname} => #{filepath}"
            end

            # modify and send back ACK packet to source
            tmp = packet.srcHostname
            packet.srcHostname = @node.hostname
            packet.dstHostname = tmp
            packet.payload = [failure, fname, origTime, bytesTransferred]
            packet.ack = true
            forwardPacket(packet)
        else
            # ACK pass
            if (retval == 1)
                # if we're back at the source node, we print the appropriate success/failure method
                failure = (packet.payload[0] == "true")
                filename = packet.payload[1]
                initialTime = packet.payload[2].to_f
                bytesTransferred = packet.payload[3].to_i

                if (failure)
                    puts "FTP ERROR: #{filename} => #{packet.srcHostname} INTERRUPTED AFTER #{bytesTransferred} BYTES"
                else
                    time = getLocalTime() - initialTime
                    speed = bytesTransferred.to_f / time

                    # round to 3 decimal digits (Ruby 1.8.7 doesn't support arguments to round method of floats)
                    time = (time * 1000.0).round.to_f / 1000.0
                    speed = (speed * 1000.0).round.to_f / 1000.0

                    puts "#{filename} => #{packet.srcHostname} IN #{time} SECS AT #{speed} BYTES/SEC"
                end
            end
        end
    end

    # BLACKHOLE (forward and ack)
    def onReceive_BLACKHOLE(packet)
        retval = forwardPacket(packet)

        if (retval == 1)
            if (!packet.ack)
                # modify and send back ACK packet to source
                tmp = packet.srcHostname
                packet.srcHostname = packet.dstHostname
                packet.dstHostname = tmp
                packet.ack = true

                forwardPacket(packet)
            else
                # record current time and drop packet
                @node.timeLastHeardFrom["#{@node.hostname}to#{packet.srcHostname}"] = getLocalTime()
            end
        end
    end

    # FAILURE
    def onReceive_FAILURE(packet)
        retval = forwardPacket(packet)

        if (retval == 1)
            # if we're the target, print out the appropriate failure message
            # based on the message type
            typ = packet.payload[0]
            if (typ == "SNDMSG")
                puts "SENDMSG ERROR: HOST UNREACHABLE (because we got a failure packet)"
            elsif (typ == "PING")
                puts "PING ERROR: HOST UNREACHABLE (because we got a failure packet)"
            elsif (typ == "TRACEROUTE")
                puts "TIMEOUT ON " + packet.payload[2 + 3] + " (because we got a failure packet)"
            elsif (typ == "FTP")
                puts "FTP ERROR: #{packet.payload[2]} => #{packet.srcHostname} INTERRUPTED AFTER 0 BYTES"
            else
                #puts packet.to_s
            end
        end
    end

    # FRAGMENT
    def onReceive_FRAGMENT(packet)
        retval = forwardPacket(packet)

        if (retval == 1)
          num = packet.payload[0]
          total = packet.payload[1]
          uid = packet.payload[2]
          type = packet.payload[3]
          data = packet.payload[4]

          hasKey = false

          @lock.synchronize {
            hasKey = @fragments.has_key?(uid)
          }
            if (hasKey)
              thisData = ""
              @lock.synchronize {
                thisData = @fragments[uid]
              }
              thisData[num] = data
              if (thisData.size == total.to_i)
                #put it back together
                payload = ""
                for i in 1..total.to_i do
                  payload = payload + Base64.decode64(thisData[i.to_s].to_s)
                end
                @lock.synchronize {
                  @fragments.delete(uid)
                }

                p = Packet.new(type, packet.srcHostname, packet.dstHostname, packet.seqNum)
                p.payload = payload.split(" ")

                if p.type == "HELLO"
                    onReceive_HELLO(p)
                elsif p.type == "LINKSTATE"
                    onReceive_LINKSTATE(p)
                elsif p.type == "SNDMSG"
                    onReceive_SNDMSG(p)
                elsif p.type == "PING"
                    onReceive_PING(p)
                elsif p.type == "FAILURE"
                    onReceive_FAILURE(p)
                elsif p.type == "TRACEROUTE"
                    onReceive_TRACEROUTE(p)
                elsif p.type == "FTP"
                    onReceive_FTP(p)
                elsif p.type == "BLACKHOLE"
                    onReceive_BLACKHOLE(p)
                elsif p.type == "FRAGMENT"
                    onReceive_FRAGMENT(p)
                elsif p.type == "CLOCKSYNC"
                    onReceive_CLOCKSYNC(p)
                end

              else
                @lock.synchronize {
                  @fragments[uid] = thisData
                }
              end
            else
              thisData = {num => data}
              @lock.synchronize {
                @fragments[uid] = thisData
              }
            end
        end
    end

    # CLOCKSYNC
    def onReceive_CLOCKSYNC(packet)
        retval = forwardPacket(packet)

        if (retval == 1)
          # CLOCKSYNC payload contains boolean (true if response, false if initial)
          # + float (time packet was sent out)
          if (packet.payload[0] == "true")
              # if this is a response, we need to store the data in the global variable
              @lock.synchronize {
                  @clocksyncs[packet.srcHostname] = packet.payload[1]
              }
          else
              # if this is an initial packet, we need to send a response
              response = Packet.new("CLOCKSYNC", packet.dstHostname, packet.srcHostname, @seqNum)
              response.payload[0] = "true"
              response.payload[1] = getLocalTime()
              returnval = forwardPacket(response)
              timeStr = Time.at(getLocalTime()).strftime("%H:%M:%S")
              puts "CLOCKSYNC FROM #{packet.srcHostname}: TIME = #{timeStr}"
          end
        end
    end



    # -------------------------------------------------------------------------
    # specific input handlers
    # -------------------------------------------------------------------------
    def onInput_PRINT(input)
        puts @node.routingTable.inspect
    end

    def onInput_SNDMSG(input)
        dstHostname = input[1]

        message = ""
        for i in 2 ... input.length
            message += input[i]
            if (i < input.length - 1) then message += " "; end
        end

        # special case: sending message to self
        if (dstHostname == @node.hostname)
            puts "SENDMSG: " + input[1] + " --> " + message
        else
            packet = Packet.new("SNDMSG", @node.hostname, dstHostname, @seqNum)
            packet.payload[0] = message

            retval = forwardPacket(packet)
            if (retval == -1)
                puts "SENDMSG ERROR: HOST UNREACHABLE"
            end
        end
    end

    def onInput_PING(input)
        dstHostname = input[1]
        numPings = input[2].to_i
        delay = input[3].to_f

        # special case: pinging yourself just prints 0ms however many times
        if (dstHostname == @node.hostname)
            for i in 0 .. (numPings - 1)
                puts "#{i} #{@node.hostname} 0ms"
            end
            return
        end

        # start new thread for pings
        Thread.new {
            for i in 0 .. (numPings - 1)
                # PING payload contains sub-sequence number + time packet was sent out
                packet = Packet.new("PING", @node.hostname, dstHostname, @seqNum)
                packet.payload[0] = i
                packet.payload[1] = getLocalTime()

                retval = forwardPacket(packet)
                if (retval == -1)
                    # if we can't even send the packet one node forward, print out an error
                    puts "PING ERROR: HOST UNREACHABLE (can't send to next hop)"
                else
                    # start sub-thread, which monitors timeout for this ping
                    Thread.new {
                        packetSeqNum = packet.seqNum # have to keep a local copy here so each thread has the correct number
                        outTime = getLocalTime()

                        while (getLocalTime() - outTime < @pingTimeout)
                            # busy-wait until ping timeout limit passes
                            sleep(0.05)
                        end

                        # if we haven't received the ping-back by this time, time out
                        @lock.synchronize {
                            if !(@seqsBack.include?(packetSeqNum))
                                puts "PING ERROR: HOST UNREACHABLE (timed out seqNum #{packetSeqNum})"
                            else
                                @seqsBack.delete(packetSeqNum)
                            end
                        }
                    }
                end

                # sleep on main thread
                sleep(delay)
            end
        }
    end

    def onInput_TRACEROUTE(input)
        # hopcount is initially 1
        dstHostname = input[1]
        hopcount = 1

        # generate TRACEROUTE packet -- contains current hopcount, initial time, initial
        # hopcount, and destination hostname in payload
        packet = Packet.new("TRACEROUTE", @node.hostname, dstHostname, @seqNum)
        packet.payload[0] = hopcount
        packet.payload[1] = getLocalTime()
        packet.payload[2] = hopcount
        packet.payload[3] = dstHostname

        retval = forwardPacket(packet)
        if (retval == -1)
            puts "TIMEOUT ON 0"
        else
            # print info for hopcount 0
            puts "0 #{@node.hostname} 0ms"
        end
    end

    def onInput_FTP(input)
        dstHostname = input[1]
        filename = input[2]
        dstFiledir = input[3]

        # read file into string, and unpack it into hexadecimal representation
        fileStr = File.open(filename, "rb") { |f| f.read }
        fileStr = fileStr.unpack('H*')
        fileStr = fileStr[0]

        # generate FTP packet -- contains destination directory, filename, start time,
        # and stringified file in payload
        packet = Packet.new("FTP", @node.hostname, dstHostname, @seqNum)
        packet.payload[0] = dstFiledir
        packet.payload[1] = filename
        packet.payload[2] = getLocalTime()
        packet.payload[3] = fileStr

        retval = forwardPacket(packet)
        if (retval == -1)
            puts "FTP ERROR: #{filename} => #{dstHostname} INTERRUPTED AFTER 0 BYTES"
        end
    end

    # inititate blackhole security feature
    def onInput_BLACKHOLE(input)
        @node.lock.synchronize {
            @node.routingTable.keys.each { |hname|
                if (hname != @node.hostname)
                    dstHostname = hname
                    currTime = getLocalTime()
                    @node.timeLastHeardFrom["#{@node.hostname}to#{dstHostname}"] = currTime
                end
            }
        }


        Thread.new {
            while 1
                @node.lock.synchronize {
                    @node.routingTable.keys.each { |hname|
                        if (hname != @node.hostname)
                            dstHostname = hname
                            currTime = getLocalTime()

                            packet = Packet.new("BLACKHOLE", @node.hostname, dstHostname, @seqNo)
                            retval = forwardPacket(packet)
                        end
                    }
                }
                sleep(2)
            end
        }
    end

    # removes a blackhole from the network
    def onInput_REMOVEHOLE(input)
        @node.timeLastHeardFrom.keys.each { |x|
            time = getLocalTime()
            timeLast = @node.timeLastHeardFrom[x]

            secsElapsed = time - timeLast

            if (secsElapsed > 10)
                blackHole = x.split('to')
                puts "Removing blackhole at #{blackHole[1]} from network..."

                @node.lock.synchronize {
                    @node.deleteHostname(blackHole[1])
                    @node.routingTable.clear
                    @node.updateRoutingTable()
                }
            end

        }
    end


    # synchronizes the clock
    def onInput_CLOCKSYNC(input)
        dstHostname = input[1]
        numPings = input[2].to_i
        delay = input[3].to_f

        # loop through nodes
          for i in @node.hello
              dstHostname = @node.ipToHostname[i]
              #puts "doing CLOCKSYNC with #{dstHostname}"
              # CLOCKSYNC payload contains boolean (true if response, false if initial)
              # + float (time packet was sent out)
              packet = Packet.new("CLOCKSYNC", @node.hostname, dstHostname, @seqNum)
              packet.payload[0] = false
              packet.payload[1] = getLocalTime()

              retval = forwardPacket(packet)

              #put this up here so it's more accurate
              outTime = getLocalTime()

              if (retval == -1)
                  # if we can't even send the packet one node forward, print out an error
                  #puts "CLOCKSYNC ERROR: HOST UNREACHABLE (can't send to next hop)"
              else
                  # start sub-thread, which monitors timeout for this clocksync
                  Thread.new {
                      packetHostname = packet.dstHostname # have to keep a local copy here so each thread has the correct number

                      while (getLocalTime() - outTime < @pingTimeout)
                          # busy-wait until ping timeout limit passes
                          sleep(0.05)
                      end

                      # if we haven't received the clocksync response by this time, time out
                      @lock.synchronize {
                          #puts @clocksyncs.inspect
                          if !(@clocksyncs.include?(packetHostname))
                              puts "CLOCKSYNC ERROR: HOST UNREACHABLE (timed out for host #{packetHostname})"
                          else
                              # process the data
                              delay = (getLocalTime() - outTime) / 2
                              halfDiff = ((@clocksyncs[packetHostname].to_f - delay) - outTime) / 2 # half the difference between the clocks
                              setLocalTime(getLocalTime() + halfDiff)
                              timeStr = Time.at(getLocalTime()).strftime("%H:%M:%S")
                              puts "CLOCKSYNC: TIME = #{timeStr} DELTA = #{halfDiff}"
                              @clocksyncs.delete(packetHostname)
                          end
                      }
                  }
              end

                # sleep on main thread
                sleep(delay)
            end
    end


    # -------------------------------------------------------------------------
    # underlying basic functionality
    # -------------------------------------------------------------------------

    # send packet to outgoing IP
    def sendPacket(packet, ip, port = nil)

        # resolve port if we weren't passed one
        if (port.nil?)
            port = @node.hostnameToPort[@node.ipToHostname[ip]]
        end

        payload = packet.payload.join(" ")
        if (payload.length > @maxPayloadSize)
          #puts "packet is being fragmented"
          newPayloads = payload.scan(/.{1,#{@maxPayloadSize}}/)
          numPieces = newPayloads.length
          newPackets = Array.new
          uid = 1 + rand(10000)
          for i in 0...numPieces do
            # update sequence number for every unique packet sent (successful or
            # unsuccessful)
            @lock.synchronize {
                @seqNum = @seqNum + 1
            }
            newPacket = Packet.new("FRAGMENT", packet.srcHostname, packet.dstHostname, @seqNum)
            newPacket.payload = [i+1,numPieces,uid,packet.type,Base64.encode64(newPayloads[i]).delete!("\n")]
            newPackets.push(newPacket)
          end
        else
          # update sequence number for every unique packet sent (successful or
          # unsuccessful)
          @lock.synchronize {
              @seqNum = @seqNum + 1
          }
          newPackets = [packet]
        end

        newPackets.each do |newPacket|

            # create new thread in case the connection stalls
            Thread.new {
                # run each thread for the ping timeout amount
                startTime = getLocalTime()
                success = false

                while (getLocalTime() - startTime < @pingTimeout)
                    str = newPacket.to_s
                    begin
                        client = TCPsocket.new(ip, port)
                        if newPacket.type != "HELLO"
                          #puts "sending string #{str}"
                        end
                        client.write(str)

                        success = true
                        break
                    rescue

                    end
                end

                # if the connection failed, then create a FAILURE packet, UNLESS
                # the packet we wanted to send was already a FAILURE packet
                if (!success && packet.type != "FAILURE")
                    sendFailurePacket(packet)
                end
            }
          end
    end

    # send hello packets to neighbors
    def sayHello()
        @node.neighborIPs.each { |ip|
            #if !(@node.saidHello?(ip))
                outgoingInterface = @node.neighborToInterface[ip]

                packet = Packet.new("HELLO", @node.hostname, @node.ipToHostname[ip], @seqNum)
                packet.payload[0] = outgoingInterface

                sendPacket(packet, ip)
            #end
        }
    end

    # flood neighbors (that we've said hello to)
    def flood(packet)
        @node.neighborIPs.each{ |ip|
            if (@node.saidHello?(ip) && (@node.ipToHostname[ip] != @node.hostname))
                sendPacket(packet, ip)
            end
        }
    end

    # send link state packets
    def sendLinkStatePacket()
        @node.neighborIPs.each { |ip|
            @node.neighborIPs.each { |ip2|
                # send IP [ip] the node's connection information for all other IPs [ip2]
                if (ip != ip2 && @node.saidHello?(ip) && @node.saidHello?(ip2))
                    outgoingInterface = @node.neighborToInterface[ip2]
                    targetHostname = @node.ipToHostname[ip2]
                    weight = @node.validWeights.ipMap[outgoingInterface][ip2]

                    packet = Packet.new("LINKSTATE", @node.hostname, @node.ipToHostname[ip], @seqNum)
                    packet.payload[0] = @node.hostname
                    packet.payload[1] = outgoingInterface
                    packet.payload[2] = targetHostname
                    packet.payload[3] = ip2
                    packet.payload[4] = weight
                    packet.payload[5] = @node.port
                    sendPacket(packet, ip)
                end
            }
        }
    end

    # forwards packet to its destination host
    #     (returns 1 if we are the host, 0 if not, -1 if error)
    def forwardPacket(packet)
        if (packet.dstHostname == @node.hostname)
            return 1
        end

        # if it's not us, we have to find where to forward the packet to
        forwardIP = nil

        # check if destination hostname is one of our neighbors; if it is, forward
        # along that path
        @node.neighborIPs.each { |ip|
            if (@node.saidHello?(ip))
                h = @node.ipToHostname[ip]
                if (h == packet.dstHostname)
                    forwardIP = ip
                    break
                end
            end
        }

        # if it isn't a direct neighbor, we need to use our forwarding table
        if (forwardIP.nil?)
            forwardHostInfo = @node.routingTable[packet.dstHostname]

            # if node isn't contained in routing table, return error
            if (forwardHostInfo.nil? || forwardHostInfo.empty?)
                return -1
            end
            forwardHostname = forwardHostInfo[0]

            # TO ALEX: i don't really understand what this is supposed to do, and it seems like it
            # messes up SNDMSG, but i'm leaving it here just in case
            #if forwardIP == nil
            #    while (@node.routingTable[forwardHostname][0] != @node.hostname)
            #        forwardHostname = @node.routingTable[forwardHostname][0]
            #    end
            #end

            # find out which IP corresponds to our hostname
            @node.neighborIPs.each { |ip|
                if (@node.ipToHostname[ip] == forwardHostname)
                    forwardIP = ip
                    break
                end
            }

            # again, if the hostname in our routing table couldn't be matched to an IP,
            # return an error
            if (forwardIP.nil?)
                return -1
            end
        end

        # finally, send the message across TCP
        sendPacket(packet, forwardIP)

        return 0
    end

    # form special packet that's sent back in case of a failure
    def sendFailurePacket(packet)
        f = Packet.new("FAILURE", @node.hostname, packet.srcHostname, packet.seqNum)
        f.payload[0] = packet.type
        f.payload[1] = packet.dstHostname

        # append original payload to FAILURE packet
        for i in 0 ... packet.payload.size
            f.payload[2 + i] = packet.payload[i]
        end

        forwardPacket(f)
    end

end
