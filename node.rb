require 'socket'
require 'thread'
require 'csv'
require 'set'

Thread::abort_on_exception = true

# data structure for a weight
class Weight
    def initialize()
        @srcHostname = ""
        @srcIp = ""
        @dstHostname = ""
        @dstIp = ""
        @cost = -1
    end

    def flip()
        # same edge, except in the reverse direction
        ret = Weight.new
        ret.srcHostname = dstHostname
        ret.srcIp = dstIp
        ret.dstHostname = srcHostname
        ret.dstIp = srcIp
        ret.cost = cost

        return ret
    end

    attr_accessor :srcHostname, :srcIp, :dstHostname, :dstIp, :cost
end

# easy collection for accessing a node's weights in 3 different ways (IP-to-IP hash,
# hostname-to-hostname hash, array of Weight objects).
#     access through hashmap is O(1); insertion is O(n). TODO: can we make insertion
#     O(1) too (e.g. using pointers?)
class NodeWeights
    def initialize()
        # IP-to-IP weights
        @ipMap = Hash.new{|hash, key| hash[key] = Hash.new}

        # hostname-to-hostname weights
        @hnameMap = Hash.new{|hash, key| hash[key] = Hash.new}

        # array of Weight objects
        @collection = Array.new
    end

    def push(w)
        # add weights bidirectionally
        @hnameMap[w.srcHostname][w.dstHostname] = w.cost.to_f
        @hnameMap[w.dstHostname][w.srcHostname] = w.cost.to_f

        @ipMap[w.srcIp][w.dstIp] = w.cost.to_f
        @ipMap[w.dstIp][w.srcIp] = w.cost.to_f

        updateCollection(w)
        updateCollection(w.flip())
    end

    def updateCollection(w)
        # update Weight object if one already exists from the source IP to the dest IP
        @collection.each { |item|
            if (item.srcIp == w.srcIp && item.dstIp == w.dstIp)
                item.cost = w.cost
                return
            end
        }

        # if not, add something new
        @collection.push(w)
    end

    def delete(ip, hname)
        if @ipMap[ip]
            @ipMap.delete(ip)
        end

        if @hnameMap[hname]
            @hnameMap.delete(hname)
        end

        @ipMap.keys.each { |y|
            @ipMap[y].keys.each { |z|
                if (z == ip)
                    @ipMap.delete(y)
                end
            }
        }

        @hnameMap.keys.each { |y|
            @hnameMap[y].keys.each { |z|
                if (z == hname)
                    @hnameMap.delete(y)
                end
            }
        }

        @collection.delete_if { |item|
            if (item.srcIp == ip || item.dstIp == ip || \
                item.srcHostname == hname || item.dstHostname == hname)
                return true
            else
                return false
            end
        }
    end

    attr_accessor :ipMap, :hnameMap, :collection
end

class Node
    def initialize()
        # [hostname]: hostname of current node
        @hostname = ""

        # [hello]: set of IP addresses
        #     essentially signifies "valid" lines to send things on -- which of the
        #     current's node neighbors has it talked to, and received an ack back from (with
        #     a HELLO message)?
        @hello = Set.new

        # [allWeights]: all weights we've read from our weights CSV
        @allWeights = NodeWeights.new

        # [validWeights]: valid weights for the purposes of the protocol
        @validWeights = NodeWeights.new

        # [sequenceNumPath]: map srcIp => dstIp => num, of last sequence number seen for path
        @sequenceNumPath = Hash.new{|hash, key| hash[key] = Hash.new}

        # [routingTable]: routing table.
        @routingTable = Hash.new

        # [timeLastHeardFrom]: used to keep track of nodes that are responding, when blackhole
        #     feature is enabled
        @timeLastHeardFrom = Hash.new

        # [interfaces]: array of all the interfaces that are associated with the node
        @interfaces = []

        # [neighborIPs]: array of neighboring IP addresses (outward)
        @neighborIPs = []

        # [ipToHostname]: map of IP => hostname, for self/neighbor nodes
        @ipToHostname = Hash.new

        # [hostnameToPort]: map of hostname => port, for self/neighbor nodes
        @hostnameToPort = Hash.new

        # [lock]: mutex for this node, because multithreading
        @lock = Mutex.new

        # [nodePort]: current node's port
        @port = 4001

        # [neighborToInterface]: map of neighbor IP => node's outgoing interface
        @neighborToInterface = Hash.new


        # ------------------------------------------------------------------------------------

        # TODO: this class should not be dealing with ARGV directly
        configPath = "#{ARGV[0]}"
        @hostname = "#{ARGV[1]}"

        config =  File.open(configPath, "r")

        puts configPath

        config.each_line do |line|
            arr = line.split('=')
            if arr[0] == "nodes"
                @pathToNode = ""
                @pathToNode = arr[1].chomp!
            end
            if arr[0] == "weights"
                pathToWeights = arr[1].chomp!
                loadWeightsFile(pathToWeights)
            end
            if arr[0] == "functions"
                pathToFunctions = arr[1].chomp!
                load "#{pathToFunctions}"
            end
            if arr[0] == "updateInterval"
                @seconds = arr[1].to_i
            end
        end

        getInterfaces()
        puts "interfaces: " + @interfaces.inspect

        getNeighboringIPs()
        puts "neighborIPs: " + @neighborIPs.inspect

        getIpToHostname()
        puts "ipToHostname: " + @ipToHostname.inspect

        getHostnameToPort()
        puts "hostnameToPort: " + @hostnameToPort.inspect

        @port = @hostnameToPort[@hostname]
        puts "port: " + @port.inspect

        getNeighborToInterface()
        puts "paths: " + @neighborToInterface.inspect
    end

    def loadWeightsFile(pathToWeights)
        @allWeights = NodeWeights.new

        weightsFile = File.open("#{pathToWeights}", "r")

        weightsFile.each_line do |line| 
            arr = line.split(',')

            # parse into Weight object
            w = Weight.new
            w.cost = Integer(arr[4])
            w.srcHostname = arr[0]
            w.srcIp = arr[1]
            w.dstHostname = arr[2]
            w.dstIp = arr[3]
            @allWeights.push(w)
        end
    end

    # function to get all IP addresses associated with the current node
    def getInterfaces()
        # this actually resolves to the output of ifconfig, which we can then
        # scan for connections
        ifconfigOut = `ifconfig`

        @interfaces = Array.new

        arr = ifconfigOut.scan(/inet addr:([0-9]+.[0-9]+.[0-9]+.[0-9]+)/)
        arr.each { |ip| 
            newIp = ip[0]
            if newIp !~ /127.0.0.1/
                @interfaces.push(newIp)
            end
        }
    end

    # get neighboring IPs of [interfaces] from weights file
    def getNeighboringIPs()
        @neighborIPs = Array.new
        
        @interfaces.each { |interface|
            # get IPs that are connected to this outgoing interface, and add them
            # to our list of neighbors
            connectedIPs = @allWeights.ipMap[interface].keys
            @neighborIPs.concat(connectedIPs)
        }
    end

    # creates IP => hostname hash table, for current node and its neighbors
    def getIpToHostname()
        @ipToHostname = Hash.new
        
        @interfaces.each { |interface|
            @allWeights.collection.each { |weight|
                if (interface == weight.dstIp || @hostname == weight.srcHostname)
                    @ipToHostname[weight.srcIp] = weight.srcHostname
                end
            }
        }
    end

    # function to get all ports associated with self/neighbor nodes
    def getHostnameToPort()
        @hostnameToPort = Hash.new

        # for every node we recognize, create an empty spot
        @allWeights.collection.each { |weight| 
            if @ipToHostname[weight.srcIp]
                @hostnameToPort[weight.srcHostname] = ""
            end
        }

        nodeFile = File.open("#{@pathToNode}", "r")

        nodeFile.each_line do |line|
            arr = line.split('=')

            if @hostnameToPort["#{arr[0]}"]
                @hostnameToPort["#{arr[0]}"] = "#{arr[1].delete("\n").to_i}"
            end
        end
    end

    # function to get map: neighbor IP => outgoing interface for neighbor
    def getNeighborToInterface() 
        @neighborToInterface = Hash.new

        # match each neighbor IP to its outgoing interface
        @interfaces.each { |interface|
            @allWeights.collection.each { |weight|
                if (interface == weight.srcIp)
                    @neighborToInterface[weight.dstIp] = interface
                end
            }
        }
    end

    # function to populate valid weights array, with weights of existing paths
    # to neighbors (that we've said hello to)
    def populateValidWeights()
        @allWeights.collection.each { |weight|
            if (weight.srcHostname == @hostname && saidHello?(weight.dstIp))
                validWeights.push(weight)
            end
        }
    end

    # updates routing table using the node's current knowledge of the network topology.
    # uses Djikstra's algorithm to compute all shortest paths
    #     ([routingTable] is a map: dest => [hop, cost] -- the hop we need to take
    #      to get to the node, along with its associated cost)
    def updateRoutingTable()
        @routingTable = Hash.new

        # get a map hostname => (hostname, cost)
        weightsHash = @validWeights.hnameMap

        # implementation of Djikstra's algorithm -- follows Wikipedia psuedocode
        # pretty closely
        unvisited = Array.new

        weightsHash.keys.each { |node|
            @routingTable[node] = [nil, Float::MAX]
            unvisited.push(node)
        }

        @routingTable[@hostname] = [@hostname, 0]

        while !unvisited.empty?
            # find node in [unvisited] with minimum distance
            node = unvisited[0]
            unvisited.each { |nNode|
                if (@routingTable[nNode][1] < @routingTable[node][1]) then
                    node = nNode
                end
            }

            # delete it from the set
            unvisited.delete(node)

            # for each neighbor that this node is connected to, that is still in the unvisited set
            weightsHash[node].keys.each { |neighbor|
                if unvisited.include?(neighbor) then
                    altRoute = @routingTable[node][1] + weightsHash[node][neighbor]
                    
                    if (altRoute < @routingTable[neighbor][1])
                        @routingTable[neighbor][0] = node
                        @routingTable[neighbor][1] = altRoute
                    end
                end
            }
        end
    end

    def deleteHostname(hname)
        ipsToDelete = Set.new

        ipToHostname.keys.each { |ip|
            if (ipToHostname[ip] == hname)
                ipsToDelete.add(ip)
            end
        }

        ipsToDelete.each { |ip|
            if (saidHello?(ip))
                hello.delete(ip)
            end

            validWeights.delete(ip, hname)
        }
    end

    def saidHello?(ip)
        return hello.include?(ip)
    end

    attr_accessor :hostname, :port, :hello, :allWeights, :sequenceNumPath,
                  :validWeights, :routingTable, :seconds, :interfaces, :neighborIPs, :ipToHostname,
                  :hostnameToPort, :neighborToInterface, :timeLastHeardFrom, :lock
end





# PROGRAM STARTS HERE
thisNode = Node.new
thisProtocol = Protocol.new(thisNode)
thisProtocol.execute()


