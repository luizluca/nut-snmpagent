#!/usr/bin/ruby -w
#
# Wrapper to convert NUT information into SNMP
#
# Author: Luiz Angelo Daros de Luca <luizluca@gmail.com>
# Created: 2009-12-10
#
# This is a script wrapper that translate the output of upsc 
# comand into a SNMP agent (pass_persist). This code use 
# The NUT.mib, converted into xml with (smidump -f xml) and
# a lot of metaprogramming to do the job.
#
# What is missing:
# - I ignored the driver parameters.
#
# What I found of docs problem:
# - Missing field: driver.version.data
# - Wrong description of power.minimum     Maximum seen apparent power (VA)
#
# TODO
# - fix problem with types without range
# - use set for ups comands like load.off
#
require "thread"

module SNMPPass
    INTEGER      =    "INTEGER"
    INTEGER32    =    "Integer32"
    TIMETICKS    =    "TIMETICKS"
    GAUGE32      =    "GAUGE32"
    GAUGE        =    GAUGE32
    COUNTER32    =    "COUNTER32"
    COUNTER64    =    "COUNTER64"
    COUNTER      =    COUNTER32
    STRING       =    "STRING"
    OCTETSTRING  =    "OCTETSTRING"
    BITS         =    OCTETSTRING
    BITSTRING    =    "BITSTRING"
    OID          =    "OID"
    IPADDRESS    =    "IPADDRESS"
    OPAQUE       =    "OPAQUE"

    def oid2num(oid)
        oid.split('.').collect{|s| s.to_i}
    end
    module_function :oid2num

    def num2oid(num)
        ".#{num.join(".")}"
    end
    module_function :num2oid

    # Return which types are numbers
    def istype_numeric?(type)
        case type
        when GAUGE, GAUGE32, INTEGER, TIMETICKS, COUNTER, INTEGER32, COUNTER32, COUNTER64
            true
        else
            false
        end
    end
    module_function :istype_numeric?

    # I'm the generic snmp agent
    # Not very usefull at this form
    class Generic
        attr_reader :oid

        # I'm the basic node of a SNMP tree
        class Element
            include Enumerable

            def []=(oid,value)
                set(oid,value)
            end

            def [](oid)
                get(oid)
            end

            def initialize(oid)
                @oid=oid
            end

            def roid2oid(roid)
                return oid + roid
            end

            def oid2roid(oid)
                raise "Unable to extract roid from oid #{SNMPPass.num2oid(oid)} for #{self}}" if not oid[0..(self.oid.size-1)]==self.oid and self.oid.size>0
                return oid[self.oid.size..-1]
            end

            attr_reader :oid
        end

        # I'm the node that have no childs but value
        class Node < Element

            def []=(roid)
                raise "#{self.class} cannot be assigned"
            end

            def initialize(oid,type,value)
                super(oid)
                @value=value
                @type=type
            end
            attr_reader :value, :type

            def get(oid)
                return self if oid == self.oid
                return nil
            end

            def getnext(oid)
                return self if (oid<=>self.oid) <0
                return nil
            end

            def to_s
                "#{self.value.inspect}:#{self.type}[#{SNMPPass.num2oid(self.oid)}] (#{self.class})"
            end

            def each(&block)
                block.call self
            end
        end

        # I does not keep a value but a block that is called when I need my value
        class DynamicNode < Node
            def initialize(oid,type,&method)
                super(oid, type, nil)
                @method=method
            end

            # Scalar value does not deal with indexes, so no next
            def value
                @method.call
            end
        end

        # I represent the fixed nodes of a SNMP tree that have childs
        # but I have none 
        class Tree < Element

            def initialize(oid)
                super(oid)
                @nodes=[]
            end

            # validate the pos argument or raise an exception
            def validate_roid(roid)
                raise "roid must be an Array! #{roid}" if not roid.kind_of? Array
                raise "roid cannot be empty! #{roid}" if not roid.size>0
            end

            # Returns the content of position. Return nil if not found
            # oid must be an array in the form: [1,2,3,4]
            def get(oid)
                roid=self.oid2roid(oid)
                return nil if roid.empty?
                validate_roid(roid)
                roid_first=roid.first
                node=@nodes[roid_first]
                return node.get(oid) if node
                return nil
            end

            # Returns the next value after the position. Return nil if the
            # element is after all items in the tree
            def getnext(oid)
                roid=[]
                roid=self.oid2roid(oid) if not (oid <=> self.oid) < 0
                roid_first = roid.first
                return nil if roid_first and roid_first > @nodes.size-1
                @nodes.each_index do
                    |index|
                    next if roid_first and roid_first > index
                    node = @nodes[index]
                    node = node.getnext(oid) if node
                    # I have some nil elements, but not the last
                    next if not node
                    return node
                end
                # It is not expected to get here
                return nil
            end

            # Sets the value at a defined position. It adds
            # subtree objects on demand.
            def set(oid,value)
                roid=self.oid2roid(oid)
                validate_roid(roid)
                roid_first=roid.first
                if roid.size>1
                    @nodes[roid_first]=self.class.new(self.oid + [roid_first]) if not @nodes[roid_first]
                    node=@nodes[roid_first]
                    return node.set(oid,value)
                end
                return @nodes[roid_first]=value
            end

            # Interact over the elements. Usefull for debugging
            def each(&block)
                # get the first
                node=getnext([])
                $DEBUG.puts "each: first node is #{node}"
                while node
                    block.call node
                    oldnode=node
                    node=getnext(node.oid)
                    $DEBUG.puts "each: next of #{oldnode} is #{node}"
                end
            end

            # I have no value
            def value
                nil
            end

            def to_s
                "Tree[#{SNMPPass.num2oid(self.oid)}]"
            end
        end

        # I represent dynamic elements of a SNMP tree, like tables
        # My data comes from a method received on Me.new. It must
        # - receives the operation (:get,:getnext) and the relative OID (roid) as argument, nil for first element
        # - returns [roid, value, type], with nil if not found
        class DynamicTree < Tree
            OP_GET=:get
            OP_GETNEXT=:getnext

            def initialize(oid, &method)
                super(oid)
                @callback=method
            end

            def get(oid)
                roid=self.oid2roid(oid)
                return nil if roid.empty?
                validate_roid(roid)
                $DEBUG.puts "get: #{SNMPPass.num2oid(oid)}"
                (roid,value,type)=@callback.call(OP_GET, roid)
                return Node.new(self.roid2oid(roid), type, value) if value
                return nil
            end

            def getnext(oid)
                roid=[]
                roid=self.oid2roid(oid) if not (oid <=> self.oid) < 0
                (roid,value,type)=@callback.call OP_GETNEXT, roid
                node_oid=(self.oid + roid)
                return Node.new(node_oid, type, value) if value
                return nil
            end

            # My structure depends on the @callback only
            def set(oid,value)
                raise "#{self.class} cannot be assigned"
            end
        end

        # Just sets the base OID and initialize the fields Tree
        def initialize(oid)
            @oid=oid
            @fields = Tree.new([])
        end

        # Keeps reading from $stdin, answering the commands
        def run
            # Do not buffer stdout
            STDOUT.sync = true

            @running=true
            while @running
                $DEBUG.puts "Waiting for command..."
                command = $stdin.gets
                break if not command
                command.chomp!.upcase!

                $DEBUG.puts "<<#{command}"

                case command
                when "PING"
                    $DEBUG.puts "New request! Answering"
                    $DEBUG.puts ">>PONG"
                    puts "PONG"

                when "GET","GETNEXT"
                    $DEBUG.puts "Now get OID"
                    oid=$stdin.gets.chomp
                    $DEBUG.puts "<<#{oid}"
                    $DEBUG.puts "Got OID '#{oid}'"
                    oid = oid.sub(/^\./,"").split(".").collect {|s| s.to_i }
                    $DEBUG.puts "Calling #{command.downcase}(#{SNMPPass.num2oid(oid)})"
                    case command
                    when "GET"
                        node=@fields.get(oid)
                    when "GETNEXT"
                        node=@fields.getnext(oid)
                    else # never gets here
                        raise "Invalid command STATE! #{command}"
                    end

                    if node == nil or (value=node.value) == nil
                        $DEBUG.puts "#{command} #{SNMPPass.num2oid(oid)} not found"
                        puts "NONE"
                        next
                    end

                    $DEBUG.puts "#{SNMPPass.num2oid(node.oid)} found with value: #{value.inspect}, type #{node.type}"
                    $DEBUG.puts ">>#{SNMPPass.num2oid(node.oid)}"
                    puts SNMPPass.num2oid(node.oid)
                    $DEBUG.puts ">>#{node.type}"
                    puts node.type
                    if not SNMPPass.istype_numeric?(node.type)
                        value="#{value}"
                    else
                        case node.type
                            when COUNTER32
                                # Start all over again after 2**32
                                value="#{(value % 1 << 32).to_i.to_s}"
                            when COUNTER64
                                # Start all over again after 2**64
                                value="#{(value % 1 << 64).to_i.to_s}"
                            else
                                value="#{value.to_i.to_s}"
                        end
                    end
                    $DEBUG.puts ">>#{value}"
                    puts value

                    $DEBUG.puts "Finished command!"
                    $DEBUG.flush

                when "SET"
                    # Not yet needed any kind of set comand
                    put "not-writable"
                else
                    raise "Unknown command '#{command}'"
                end
            end
        end

        # Simulate a snmpwalk over this object
        def walk
            @fields.collect { |node| "#{SNMPPass.num2oid(node.oid)} = #{node.value.inspect} (#{node.type})"}.join("\n")
        end

        # Add a node to the snmptree
        def add_node(node)
            $DEBUG.puts "Registering #{SNMPPass.num2oid(node.oid)} with #{node}"
            @fields[node.oid]=node
        end
    end

    # I use the xml output of smidump -f xml as information
    # inorder to build my scructure.
    #
    # 1) Scalar values
    # The snmp scalar values like exampleValue will call the method exampleValue()
    # with no arguments. The result must be nil, if missing or the value
    #
    # 2) Tables
    # Tables uses two types of methods. One with the table name gets the indexes
    # received no arguments and returns the values of all table rows indexes.
    # For single-level index tables, it can be [1,2,3] or [[1],[2],[3]]. For multiple-
    # level index tables, it must be [[1,1],[1,2],[2,1]]].
    # The other type of method that table uses is to access the column value. It has the 
    # same name of the snmp object and receives the row indexes as arguments. 
    #
    # 3) Types:
    # Values received from functions are passed "as is" to the to_s function and printed
    # as result. There is a special treatment for real values represented as integer.
    # As snmp does not have float, it uses integer values with format helpers in order to place
    # the decimal simbol. The format_value() function uses this information (d-x) in order 
    # to multiply the value by 10**cases before passing it to the to_s function
    #
    class GenericWithMib < Generic
        require 'rexml/document'

        attr_reader :indexes, :columns, :types, :decimals

        def initialize(mibxml)
            mib = REXML::Document.new mibxml
            root = mib.root
            @module_name = root.elements["module"].attributes["name"]
            noderoot_name = root.elements["module"].elements["identity"].attributes["node"]
            oid=SNMPPass.oid2num(root.elements["nodes/node[@name='#{noderoot_name}']"].attributes["oid"])
            super(oid)

            # Load MIB declared types
            @types=Hash.new; @decimals=Hash.new
            @enums=Hash.new
            prepare_types(root.elements["typedefs"])

            @indexes=Hash.new
            @columns=Hash.new
            root.elements["nodes"].elements.each do
                |element|
                case element.name
                when "node"
                    #nothing to do
                when "table"
                    prepare_table(element)
                when "scalar"
                    prepare_scalar(element)
                end
            end
        end

        # Load the declared types inside MIB. They can be used items in MIB
        def prepare_types(elements)
            elements.elements.each("typedef") do
                |typedef|
                @types[typedef.attributes["name"]]=typedef.attributes["basetype"]
                format=typedef.elements["format"].text
                if format =~ /^d-[0-9]+$/
                    @decimals[typedef.attributes["name"]]=format.sub(/^d-/,"").to_i
                end
            end
        end

        def format_value(basetype, typeOrObject, value)
            return value if not value
            return value if not SNMPPass.istype_numeric?(basetype)
            if not @decimals.include?(typeOrObject)
                return value.to_i
            else
                return (value.to_f * 10**@decimals[typeOrObject]).to_i
            end
        end

        def prepare_type(syntax, nodename)
            if syntax.elements["typedef"]
                type=syntax.elements["typedef"].attributes["basetype"]

                case type
                when "Enumeration"
                    type=INTEGER
                    @enums[nodename]=namedNumbers=Hash.new
                    syntax.elements.each("typedef/namednumber") {
                        |namedNumber| namedNumbers[namedNumber.attributes["name"]]=namedNumber.attributes["number"]}
                end

                # Check for format d-x, so values are multiplied by 10**x
                parent=syntax.elements["typedef/parent"]
                if parent
                    # Will not work if parent type is outside the module
                    parent_type=parent.attributes["name"]
                    if @decimals.include?(parent_type)
                        @decimals[nodename]=@decimals[parent_type]
                    end
                end

                case parent_type
                when "DisplayString"
                    type=STRING
                end
            else
                typename=syntax.elements["type"].attributes["name"]
                type=@types[typename]
            end

            return type
        end

        # Prepare the methods to provide the table content
        def prepare_table(element)
            name=element.attributes["name"]
            oid=SNMPPass.oid2num(element.attributes["oid"])

            # Read index and columns
            indexes=element.elements["row/linkage"].elements.collect("index") {|index| index.attributes["name"]}
            columns=element.elements["row"].elements.collect("column") do
                |column|
                column_name=column.attributes["name"]
                column_oid=column.attributes["oid"]
                column_id=SNMPPass.oid2num(column_oid).last

                $DEBUG.puts "TABLE: #{name} NAME: #{column_name} ID #{column_id}, OID: #{column_oid}"

                #column_desc=column.elements["description"].text.gsub(/^[[:blank:]\n]*/,"").gsub(/[[:blank:]\n]*$/,"")
                type=prepare_type(column.elements["syntax"], column_name)
                [column_name,column_id,type]
            end

            @indexes[name]=indexes
            @columns[name]=columns

            table=DynamicTree.new(oid){|op, *roid| dynamic_tree_callback(name, op, *roid) }
            add_node(table)
        end

        def dynamic_tree_callback(tablename, op, roid)
            #$DEBUG.puts "callback #{op} DynamicTree for #{roid.inspect}"

            indexes=@indexes[tablename]
            columns=@columns[tablename]

            rows_indexes=self.send(tablename)
            return nil if not rows_indexes
            rows_indexes=rows_indexes.collect do
                |row_indexes|
                # Normalize it as an array as multiple indexed table can have many index numbers
                row_indexes=[row_indexes] if not row_indexes.kind_of? Array
                raise "Inconsistent size of indexes for #{tablename}. Should be: #{indexes.size}, got: #{row_indexes.size}" if not indexes.size == row_indexes.size
                row_indexes
            end

            case op
            when DynamicTree::OP_GET
                $DEBUG.puts "GETting table #{tablename} at #{roid.inspect}"
                return nil if roid.size < indexes.size + 1 + 1
                # The roid is in the form [1,col,idx1,idx2,...]
                (node_entry, node_column)=roid[0..1]
                node_index=roid[2..-1]
                (column_name,column_id,column_type)=columns.detect {|(column_name,column_id,column_type)| column_id==node_column}
                return nil if not column_name
                return nil if not rows_indexes.include?(node_index)
                $DEBUG.puts "Calling #{column_name}(#{node_index.inspect})"
                value = self.send(column_name,*node_index)
                value = format_value(column_type,column_name,value)
                return [roid, value, column_type]

            when DynamicTree::OP_GETNEXT
                $DEBUG.puts "Going through table #{tablename} with indexes: #{rows_indexes.inspect}"
                value=nil
                row_column_roid=nil
                columns.detect do
                    |(column_name,column_id,column_type)|
                    rows_indexes.detect do
                        |row_indexes|
#                         $DEBUG.puts "Checking for table #{tablename}, column #{column_name} with indexes: #{row_indexes.inspect}"
                        row_column_roid=[1, column_id] + row_indexes
#                         $DEBUG.puts "Looking for next roid #{roid.inspect} X #{row_column_roid.inspect}"
                        if (not roid or roid.empty?) or ((roid <=> row_column_roid) < 0)
                            $DEBUG.puts "Calling #{column_name}(#{row_indexes.join(",")})"
                            value=self.send(column_name, *row_indexes)
                            value=format_value(column_type,column_name,value) if value
                        else
                            nil
                        end
                    end
                end

                return [row_column_roid, value, column_type]
            end
        end

        def prepare_scalar(element)
            name=element.attributes["name"]
            oid=SNMPPass.oid2num(element.attributes["oid"])
            type=prepare_type(element.elements["syntax"], name)
            add_node(DynamicNode.new(oid,type) { self.send(name) })
        end
    end

    # I'm the first part specific to NUT. I implement the missing parts that GenericWithMib
    # expects to call with upsc command results. I use a lot of metaprogramming for this job.
    class NUT < GenericWithMib
        def initialize(mibxml)
            super(mibxml)
            implement_methods
        end

        # Goes through the columns and implement the missing methods, if not
        # already implemented "by hand"
        def implement_methods
            self.columns.each do|table_name,columns|
                meta=""
                if not self.respond_to? table_name
                    # Non-special tables just uses the same indexes as deviceTable
                    meta=<<-EOM
                      def #{table_name}
                          deviceTable
                      end
                    EOM
                end
                columns.each do
                    |(column_name,column_id,type)|
                    if not self.respond_to? column_name
                        $DEBUG.puts "Defining #{column_name}(*indexes)"
                        meta+=<<-EOM
                          def #{column_name}(*indexes)
                              $DEBUG.puts "Running #{column_name}(\#{indexes.inspect})"
                              (#{self.indexes[table_name].join(",")},x)=indexes
                              prop_names=mibname2prop("#{column_name}",*indexes)
                              prop_names=[prop_names] if not prop_names.kind_of? Array
                              prop_names.each { |prop_name|
                                    value=upsc("\#{deviceName(deviceIndex)} \#{prop_name}")
                                    return parse_property("#{column_name}",value) if not value==nil
                              }
                              return nil
                          end
                        EOM
                    end
                end
                eval meta
            end
        end

        # Get the UPS avaiable, collecting its name and description
        def ups
            ups=Array.new
            upsc("-L").split("\n").each do
                |line|
                (upsname, upsdesc)=line.split(": ",2)
                ups << [upsname, upsdesc]
            end
            ups
        end

        # Maps the mib object names into the upsc property.
        # There is some hacks here in order to match the correct
        # field. It also might receive indexes if the object is inside a table
        def mibname2prop(name,*indexes)
            parts=[name.sub(/([a-z]+).*/,"\\1")]
            name.to_s.scan(/[A-Z][a-z]+/) {|tok| parts << tok.downcase }

            case parts.first
            when "outlet"
                raise "Invalid outlet size. Should be 2, got: #{indexes.inspect}" if not indexes.size == 2
                (deviceIndex, outletIndex)=indexes
                # HACK: outlet.0. might also be outlet.
                if outletIndex.to_s=="0"
                    props=[parts.join(".")]
                    parts.insert(1,"#{outletIndex}")
                    props << parts.join(".")
                    return props
                end

                parts.insert(1,"#{outletIndex}")

            when "threephase"
                raise "Invalid threephase size. Should be 4, got: #{indexes.inspect}" if not indexes.size == 4
                (deviceIndex, threephaseDomain, threephaseSubDomain, threephaseContext)=indexes
                domain=@enums["threephaseDomain"].invert[threephaseDomain.to_s]
                subdomain=@enums["threephaseSubdomain"].invert[threephaseSubDomain.to_s]
                context=@enums["threephaseContext"].invert[threephaseContext.to_s]
                context=context.sub(/([0-9])([ln])/,"\\1-\\2").upcase
                parts[0]=domain
                parts.insert(1,context) if not context=="NONE"
                # HACK: input.mains. is input.
                # HACK: output.load is output.
                parts.insert(1,subdomain) if not ["mains","load"].include?(subdomain)
            end

            return parts.join(".")
        end

        # Some values can come in a string form like (yes/no,on/off,
        # servicebypass/bypass/...). Convert them using the MIB information
        def parse_property(name,value)
            return value if not @enums.include?(name) or not @enums[name].include?(value)
            @enums[name][value]
        end

        def serverInfo
            upsc("server.info")
        end

        def serverVersion
            upsc("server.version")
        end
    
        # Device table depends on the number of ups returned bu upsc -L
        def deviceTable
            (1..ups.size).to_a
        end

        def deviceIndex(deviceIndex)
            deviceIndex
        end

        def deviceName(deviceIndex)
            (name,desc)=ups[deviceIndex-1]
            name
        end

        def deviceDesc(deviceIndex)
            (name,desc)=ups[deviceIndex-1]
            desc
        end

        # In order to the the amount of outlets, I need to parse the upsc command
        def outletTable
            idx=deviceTable.collect do
                |dev_id|
                dev_name = deviceName(dev_id)
                upsc(dev_name).split("\n").
                    collect {|line| line.split(":",2).first.split(".") }.
                    select {|parts| parts[0] == "outlet" }.
                    # HACK: outlet.0 is also outlet.
                    collect {|parts| parts[1]="0" if not parts[1] =~ /^[0-9]+$/; parts}.
                    collect {|parts| parts[1].to_i }.uniq.sort.
                    collect {|outlet_id| [dev_id, outlet_id] }
            end.inject([],:+)
            idx
        end

        def outletIndex(deviceIndex, outletIndex)
            outletIndex
        end

        # In order to the the threephase context and domains avaiable, I need to parse
        # the upsc command
        # TODO: I'm doing brute-force here. As side-effect, all rows are present
        def threephaseTable
            idx=deviceTable.collect do
                |dev_id|
                indexes_for_device=[]

                if inputPhases(dev_id)=="3"
                    #"mains","bypass","servicebypass"
                    indexes_for_device +=
                        [1,2,3].collect {|subdomain|
                            (0..10).collect {|context|
                                [dev_id, 1, subdomain, context]
                            }
                        }.inject([],:+)
                #    indexes_for_device << [dev_id,1,1,0]
                end

                if outputPhases(dev_id)=="3"
                    #"bypass","servicebypass","load","inverter"
                    indexes_for_device +=
                        [2,3,4,5].collect {|subdomain|
                            (0..10).collect {|context|
                                [dev_id, 2, subdomain, context]
                            }
                        }.inject([],:+)
                #    indexes_for_device << [dev_id,2,4,0]
                end

                indexes_for_device
            end.inject([],:+)
        end

        def threephaseDomain(deviceIndex, threephaseDomainIndex, threephaseSubDomainIndex, threephaseContext)
            threephaseDomainIndex
        end
        def threephaseSubdomain(deviceIndex, threephaseDomainIndex, threephaseSubdomainIndex, threephaseContext)
            threephaseSubdomainIndex
        end
        def threephaseContext(deviceIndex, threephaseDomainIndex, threephaseSubDomainIndex, threephaseContext)
            threephaseContext
        end

#
#       def upsc(args)
#           `upsc -L #{args}`
#       end

        def upsc(args)
            case args
            when "-L"
                #return "ups3: test3"
                return "ups2: UPS2 10 KVA Lacerda Titan Black tri-mono 10KVA (220v) Serial A08823221\nxxx: Fictious\nupsoutlet: Example outlet\nups3p1: phases1\nups3p2: phases2\nups3: test3"
            when "xxx"
                return "battery.charge: 30\nbattery.voltage: 273.60\nbattery.voltage.high: 250\nbattery.voltage.low: 210\nbattery.voltage.nominal: 240.0\nbeeper.status: enabled\ndevice.mfr: Lacerda Sistemas de Energia\ndevice.model: Titan Black tri-mono 10KVA\ndevice.serial: A08823221\ndevice.type: ups\ndriver.name: blazer_ser\ndriver.parameter.pollinterval: 2\ndriver.parameter.port: /dev/ttyUSB0\ndriver.version: 2.6.2\ndriver.version.internal: 1.51\ninput.current.nominal: 27.0\ninput.frequency: 60.0\ninput.frequency.nominal: 60\ninput.voltage: 215.0\ninput.voltage.fault: 215.0\ninput.voltage.nominal: 220\noutput.voltage: 221.0\nups.delay.shutdown: 30\nups.delay.start: 180\nups.load: 43\nups.status: OL\nups.temperature: 47.0\nups.type: online\n"
            when "ups2"
                return "battery.charge: 100\nbattery.voltage: 274.60\nbattery.voltage.high: 250\nbattery.voltage.low: 210\nbattery.voltage.nominal: 240.0\nbeeper.status: enabled\ndevice.mfr: Lacerda Sistemas de Energia\ndevice.model: Titan Black tri-mono 10KVA\ndevice.serial: A08823221\ndevice.type: ups\ndriver.name: blazer_ser\ndriver.parameter.pollinterval: 2\ndriver.parameter.port: /dev/ttyUSB0\ndriver.version: 2.6.2\ndriver.version.internal: 1.51\ninput.current.nominal: 27.0\ninput.frequency: 60.0\ninput.frequency.nominal: 60\ninput.voltage: 215.0\ninput.voltage.fault: 215.0\ninput.voltage.nominal: 220\noutput.voltage: 221.0\nups.delay.shutdown: 30\nups.delay.start: 180\nups.load: 43\nups.status: OL\nups.temperature: 47.0\nups.type: online\n"
            when "upsoutlet"
                return "outlet.0.desc: Main Outlet\noutlet.0.id: 0\noutlet.0.switchable: 1\noutlet.1.autoswitch.charge.low: 0\noutlet.1.delay.shutdown: -1\noutlet.1.delay.start: -1\noutlet.1.desc: PowerShare Outlet 1\noutlet.1.id: 1\noutlet.1.switch: 1\noutlet.1.switchable: 1\noutlet.2.autoswitch.charge.low: 0\noutlet.2.delay.shutdown: -1\noutlet.2.delay.start: -1\noutlet.2.desc: PowerShare Outlet 2\noutlet.2.id: 2\noutlet.2.switch: 1\noutlet.2.switchable: 1"
            when "ups3p1"
                return "input.phases: 3\ninput.frequency: 50.0\ninput.L1.current: 133.0\ninput.bypass.L1-L2.voltage: 398.3\noutput.phases: 3\noutput.L1.power: 35700\noutput.powerfactor: 0.82"
            when "ups3p2"
                return "input.phases: 3\ninput.L2.current: 48.2\ninput.N.current: 3.4\ninput.L3-L1.voltage: 405.4\ninput.frequency: 50.1\noutput.phases: 1\noutput.current: 244.2\noutput.voltage: 120\noutput.frequency.nominal: 60.0"                     when "ups3"
                return "battery.charge: 100\nbattery.charge.low: 20\nbattery.runtime: 2525\nbattery.type: PbAc\ndevice.mfr: EATON\ndevice.model: Ellipse MAX 1100\ndevice.serial: ADKK22008\ndevice.type: ups\ndriver.name: usbhid-ups\ndriver.parameter.pollfreq: 30\ndriver.parameter.pollinterval: 2\ndriver.parameter.port: auto\ndriver.version: 2.4.1-1988:1990M\ndriver.version.data: MGE HID 1.12\ndriver.version.internal: 0.34\ninput.sensitivity: normal\ninput.transfer.boost.low: 185\ninput.transfer.high: 285\ninput.transfer.low: 165\ninput.transfer.trim.high: 265\ninput.voltage.extended: no\noutlet.1.desc: PowerShare Outlet 1\noutlet.1.id: 2\noutlet.1.status: on\noutlet.1.switchable: no\noutlet.desc: Main Outlet\noutlet.id: 1\noutlet.switchable: no\noutput.frequency.nominal: 50\noutput.voltage: 230.0\noutput.voltage.nominal: 230\nups.beeper.status: enabled\nups.delay.shutdown: 20\nups.delay.start: 30\nups.firmware: 5102AH\nups.load: 0\nups.mfr: EATON\nups.model: Ellipse MAX 1100\nups.power.nominal: 1100\nups.productid: ffff\nups.serial: ADKK22008\nups.status: OL CHRG\nups.timer.shutdown: -1\nups.timer.start: -1\nups.vendorid: 0463"
            when "server.info"
                return "serverinfo example"
            when "server.version"
                return "test server version"
            when /[[:alnum:]]+ [[:alnum:]\.]+/
                (name,prop)=args.split(" ")
                found_line=upsc(name).split("\n").detect {|line| prop==line.split(": ",2).first }
                return found_line.split(": ",2).last if found_line
            end
            nil
        end
    end

end

$DEBUG=File.open("/dev/null","w")
mode=:run
while ARGV.size>0
    case ARGV.first
    when "-d",'--debug'
        $DEBUG=File.open("/dev/stderr","w")
    when "-f",'--filelog'
        $DEBUG=File.open("/tmp/snmp.log","w")
    when "-s","--syslog"
        $DEBUG=IO.popen("logger -t snmp", "w")
    when "-t","--test"
        (in_rd,in_wr)=IO.pipe
        (out_rd,out_wr)=IO.pipe

        $realin=$stdin
        $realout=$stdout
        $stdin=in_rd
        $stdout=out_wr
        wr=in_wr
        rd=out_rd
        Thread.new do
            $DEBUG.puts "Test: Testing PING"
            $realout.puts ">>PING"
            wr.puts "PING"
            pong = rd.gets
            $realout.puts "<<#{pong}"
            raise "Test: Invalid PING response" if not pong == "PONG\n"
            $realout.puts ""
            $DEBUG.puts "Test: PING OK"

            oids=[".1.3.6.1.4.1.26376.99",
                  ".1.3.6.1.4.1.26376.99.1.7",
                  ".1.3.6.1.4.1.26376.98.1.7",
                  ".1.3.6.1.4.1.26376.99.1.7.1.3.3.1"]
            oids.each do
                |oid|
                $realout.puts ">>GETNEXT"
                wr.puts "GETNEXT"
                $realout.puts ">>#{oid}"
                wr.puts oid

                #wr.puts "PING"
                nextoid=rd.gets.chomp
                $realout.puts "<<#{nextoid}"
                type=rd.gets.chomp
                $realout.puts "<<#{type}"
                value=rd.gets.chomp
                $realout.puts "<<#{value}"
                $DEBUG.puts "NEXTOID = #{nextoid}","TYPE = #{type}","VALUE = #{value}"
                $realout.puts ""
            end
            oids=[".1.3.6.1.4.1.26376.99.13.7",
                  ".1.3.6.1.4.1.26376.100.1.7"
                  ]
            oids.each do
                |oid|
                $realout.puts ">>GETNEXT"
                wr.puts "GETNEXT"
                $realout.puts ">>#{oid}"
                wr.puts oid

                #wr.puts "PING"
                none=rd.gets.chomp
                $realout.puts "<<#{none}"
                raise "Missing oid not responded correctly #{none}" if not none=="NONE"
                $realout.puts ""
            end

            $DEBUG.puts "Test: GETNEXT OK"

            oids=[".1.3.6.1.4.1.26376.99.1.7.1.3.3.1",
                  ".1.3.6.1.4.1.26376.99.1.7.1.4.3.2"
                 ]
            oids.each do
                |oid|
                $realout.puts ">>GET"
                wr.puts "GET"
                $realout.puts ">>#{oid}"
                wr.puts oid

                #wr.puts "PING"
                node_oid=rd.gets.chomp
                $realout.puts "<<#{node_oid}"
                type=rd.gets.chomp
                $realout.puts "<<#{type}"
                value=rd.gets.chomp
                $realout.puts "<<#{value}"
                $DEBUG.puts "OID = #{node_oid}","TYPE = #{type}","VALUE = #{value}"
                raise "Invalid!!! #{node_oid.inspect}, #{oid.inspect}" if not node_oid == oid
                $realout.puts ""
            end

            oids=[".1.3.6.1.4.1.26376.99.1",
                  ".1.3.6.1.4.1.26376.99.1.7.1.4.3.222",
                  ".1.3.6.1.4.1.26376.99.1.7.1.4.4.222"]
            oids.each do
                |oid|
                $realout.puts ">>GET"
                wr.puts "GET"
                $realout.puts ">>#{oid}"
                wr.puts oid

                #wr.puts "PING"
                none=rd.gets.chomp
                $realout.puts "<<#{none}"
                raise "Missing oid not responded correctly #{none}" if not none=="NONE"
                $realout.puts ""
            end
            $DEBUG.puts "Test: GET OK"

            $DEBUG.puts "Test: Exiting..."
            exit 1
        end
    when "-w",'--walk'
        $DEBUG.puts "Starting walk..."
        mode=:walk
    when "-h","--help","-?"
        $stderr.puts <<-EOF
            TODO
            Use:

            $0 OID parameters

            i.e.:

            #{$0} 1.3.6.1.4.1.26376.1.1.2

            EOF
        exit 1
    else
        $stderr.puts "Invalid option #{ARGV[0]}. See #{$0} --help"
        exit 1
    end
    ARGV.shift
end

begin
    snmp = SNMPPass::NUT.new `sed -e '1,/^__END__/d' #{$0}`
    case mode
    when :walk
        puts snmp.walk
    when :run
        snmp.run
    end
rescue
    $DEBUG.puts "Program aborted!"
    $DEBUG.puts $!
    $DEBUG.puts $!.backtrace
    $DEBUG.flush
    exit 1
end

__END__
<?xml version="1.0"?>
<!DOCTYPE smi SYSTEM "http://www.ibr.cs.tu-bs.de/projects/nmrg/smi.dtd">

<!-- This module has been generated by smidump 0.4.8. Do not edit. -->

<smi xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.ibr.cs.tu-bs.de/projects/nmrg/smi.xsd">
  <module name="NUT-MIB" language="SMIv2">
    <organization>
        Network UPS Tools
    </organization>
    <contact>
                Luiz Angelo Daros de Luca
        E-mail: luizluca@gmail.com
    </contact>
    <description>
        The MIB module list information about local configured UPS
        managed by NUT.
    </description>
    <revision date="2012-05-23 00:00">
      <description>
          First release
      </description>
    </revision>
    <identity node="nutMIB"/>
  </module>

  <imports>
    <import module="SNMPv2-SMI" name="MODULE-IDENTITY"/>
    <import module="SNMPv2-SMI" name="OBJECT-TYPE"/>
    <import module="SNMPv2-SMI" name="Integer32"/>
    <import module="SNMPv2-SMI" name="enterprises"/>
    <import module="SNMPv2-TC" name="DisplayString"/>
    <import module="SNMPv2-TC" name="TEXTUAL-CONVENTION"/>
    <import module="SNMPv2-CONF" name="MODULE-COMPLIANCE"/>
    <import module="SNMPv2-CONF" name="OBJECT-GROUP"/>
  </imports>

  <typedefs>
    <typedef name="DeviceIndexType" basetype="Integer32" status="current">
      <range min="1" max="2147483647"/>
      <format>d</format>
      <description>
          A unique value, greater than zero, for each device. It is
          recommended that values are assigned contiguously starting
          from 1.
      </description>
    </typedef>
    <typedef name="OutletIndexType" basetype="Integer32" status="current">
      <range min="0" max="2147483647"/>
      <format>d</format>
      <description>
          A unique value, greater than or equal to zero, for each outlet. It is
          recommended that values are assigned contiguously starting
          from 1.
      </description>
    </typedef>
    <typedef name="TenthInteger32" basetype="Integer32" status="current">
      <format>d-1</format>
      <description>
          A Integer32 that represents a real number, with one decimal case. I.e.: 123 for 12.3
      </description>
    </typedef>
    <typedef name="HundredthInteger32" basetype="Integer32" status="current">
      <format>d-2</format>
      <description>
          A Integer32 that represents a real number, with two decimal case. I.e.: 123 for 1.23
      </description>
    </typedef>
  </typedefs>

  <nodes>
    <node name="tresc" oid="1.3.6.1.4.1.26376">
    </node>
    <node name="nutMIB" oid="1.3.6.1.4.1.26376.99" status="current">
    </node>
    <node name="nutMIBObjects" oid="1.3.6.1.4.1.26376.99.1">
    </node>
    <table name="deviceTable" oid="1.3.6.1.4.1.26376.99.1.1" status="current">
      <description>
          A list of device.
      </description>
      <row name="deviceEntry" oid="1.3.6.1.4.1.26376.99.1.1.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular device.
        </description>
        <column name="deviceIndex" oid="1.3.6.1.4.1.26376.99.1.1.1.1" status="current">
          <syntax>
            <type module="NUT-MIB" name="DeviceIndexType"/>
          </syntax>
          <access>noaccess</access>
          <description>
              A unique value, greater than zero, for each device
          </description>
        </column>
        <column name="deviceName" oid="1.3.6.1.4.1.26376.99.1.1.1.2" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              The name of the device.
          </description>
        </column>
        <column name="deviceDesc" oid="1.3.6.1.4.1.26376.99.1.1.1.3" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              A textual string containing information about the device.
          </description>
        </column>
        <column name="deviceModel" oid="1.3.6.1.4.1.26376.99.1.1.1.4" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Device model. I.e. BladeUPS.
          </description>
        </column>
        <column name="deviceMfr" oid="1.3.6.1.4.1.26376.99.1.1.1.5" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Device manufacturer. I.e. Eaton.
          </description>
        </column>
        <column name="deviceSerial" oid="1.3.6.1.4.1.26376.99.1.1.1.6" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Device serial number (opaque string). I.e. WS9643050926.
          </description>
        </column>
        <column name="deviceType" oid="1.3.6.1.4.1.26376.99.1.1.1.7" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Device type (ups, pdu, scd). I.e. ups.
          </description>
        </column>
      </row>
    </table>
    <table name="upsTable" oid="1.3.6.1.4.1.26376.99.1.2" status="current">
      <description>
          A list of ups.
      </description>
      <row name="upsEntry" oid="1.3.6.1.4.1.26376.99.1.2.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular ups.
        </description>
        <column name="upsStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.1" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS status. I.e. OL.
          </description>
        </column>
        <column name="upsAlarm" oid="1.3.6.1.4.1.26376.99.1.2.1.2" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS alarms. I.e. OVERHEAT.
          </description>
        </column>
        <column name="upsTime" oid="1.3.6.1.4.1.26376.99.1.2.1.3" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Internal UPS clock time (opaque string). I.e. 12:34.
          </description>
        </column>
        <column name="upsDate" oid="1.3.6.1.4.1.26376.99.1.2.1.4" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Internal UPS clock date (opaque string). I.e. 01-02-03.
          </description>
        </column>
        <column name="upsModel" oid="1.3.6.1.4.1.26376.99.1.2.1.5" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS model. I.e. SMART-UPS 700.
          </description>
        </column>
        <column name="upsMfr" oid="1.3.6.1.4.1.26376.99.1.2.1.6" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS manufacturer. I.e. APC.
          </description>
        </column>
        <column name="upsMfrDate" oid="1.3.6.1.4.1.26376.99.1.2.1.7" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS manufacturing date (opaque string). I.e. 10/17/96.
          </description>
        </column>
        <column name="upsSerial" oid="1.3.6.1.4.1.26376.99.1.2.1.8" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS serial number (opaque string). I.e. WS9643050926.
          </description>
        </column>
        <column name="upsVendorid" oid="1.3.6.1.4.1.26376.99.1.2.1.9" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Vendor ID for USB devices. I.e. 0463.
          </description>
        </column>
        <column name="upsProductid" oid="1.3.6.1.4.1.26376.99.1.2.1.10" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Product ID for USB devices. I.e. 0001.
          </description>
        </column>
        <column name="upsFirmware" oid="1.3.6.1.4.1.26376.99.1.2.1.11" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS firmware (opaque string). I.e. 50.9.D.
          </description>
        </column>
        <column name="upsFirmwareAux" oid="1.3.6.1.4.1.26376.99.1.2.1.12" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Auxiliary device firmware. I.e. 4Kx.
          </description>
        </column>
        <column name="upsTemperature" oid="1.3.6.1.4.1.26376.99.1.2.1.13" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS temperature (in 0.1 degrees C). I.e. 427 (for 42.7oC).
          </description>
        </column>
        <column name="upsLoad" oid="1.3.6.1.4.1.26376.99.1.2.1.14" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Load on UPS (percent). I.e. 023.
          </description>
        </column>
        <column name="upsLoadHigh" oid="1.3.6.1.4.1.26376.99.1.2.1.15" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Load when UPS switches to overload condition ('OVER') (percent). I.e. 100.
          </description>
        </column>
        <column name="upsId" oid="1.3.6.1.4.1.26376.99.1.2.1.16" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS system identifier (opaque string). I.e. Sierra.
          </description>
        </column>
        <column name="upsDelayStart" oid="1.3.6.1.4.1.26376.99.1.2.1.17" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before restarting the load (seconds). I.e. 0.
          </description>
        </column>
        <column name="upsDelayReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.18" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before rebooting the UPS (seconds). I.e. 60.
          </description>
        </column>
        <column name="upsDelayShutdown" oid="1.3.6.1.4.1.26376.99.1.2.1.19" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait after shutdown with delay command (seconds). I.e. 20.
          </description>
        </column>
        <column name="upsTimerStart" oid="1.3.6.1.4.1.26376.99.1.2.1.20" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be started (seconds). I.e. 30.
          </description>
        </column>
        <column name="upsTimerReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.21" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be rebooted (seconds). I.e. 10.
          </description>
        </column>
        <column name="upsTimerShutdown" oid="1.3.6.1.4.1.26376.99.1.2.1.22" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be shutdown (seconds). I.e. 20.
          </description>
        </column>
        <column name="upsTestInterval" oid="1.3.6.1.4.1.26376.99.1.2.1.23" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval between self tests (seconds). I.e. 1209600 (two weeks).
          </description>
        </column>
        <column name="upsTestResult" oid="1.3.6.1.4.1.26376.99.1.2.1.24" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Results of last self test (opaque string). I.e. Bad battery pack.
          </description>
        </column>
        <column name="upsDisplayLanguage" oid="1.3.6.1.4.1.26376.99.1.2.1.25" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Language to use on front panel (* opaque). I.e. E.
          </description>
        </column>
        <column name="upsContacts" oid="1.3.6.1.4.1.26376.99.1.2.1.26" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS external contact sensors (* opaque). I.e. F0.
          </description>
        </column>
        <column name="upsEfficiency" oid="1.3.6.1.4.1.26376.99.1.2.1.27" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Efficiency of the UPS (ratio of the output current on the input current) (percent). I.e. 95.
          </description>
        </column>
        <column name="upsPower" oid="1.3.6.1.4.1.26376.99.1.2.1.28" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current value of apparent power (Volt-Amps). I.e. 500.
          </description>
        </column>
        <column name="upsPowerNominal" oid="1.3.6.1.4.1.26376.99.1.2.1.29" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal value of apparent power (Volt-Amps). I.e. 500.
          </description>
        </column>
        <column name="upsRealpower" oid="1.3.6.1.4.1.26376.99.1.2.1.30" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current value of real power (Watts). I.e. 300.
          </description>
        </column>
        <column name="upsRealpowerNominal" oid="1.3.6.1.4.1.26376.99.1.2.1.31" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal value of real power (Watts). I.e. 300.
          </description>
        </column>
        <column name="upsBeeperStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.32" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS beeper status (enabled, disabled or muted). I.e. enabled.
          </description>
        </column>
        <column name="upsType" oid="1.3.6.1.4.1.26376.99.1.2.1.33" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS type (* opaque). I.e. offline.
          </description>
        </column>
        <column name="upsWatchdogStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.34" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS watchdog status (enabled or disabled). I.e. disabled.
          </description>
        </column>
        <column name="upsStartAuto" oid="1.3.6.1.4.1.26376.99.1.2.1.35" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS starts when mains is (re)applied. I.e. yes.
          </description>
        </column>
        <column name="upsStartBattery" oid="1.3.6.1.4.1.26376.99.1.2.1.36" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Allow to start UPS from battery. I.e. yes.
          </description>
        </column>
        <column name="upsStartReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.37" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              UPS coldstarts from battery (enabled or disabled). I.e. yes.
          </description>
        </column>
      </row>
    </table>
    <table name="inputTable" oid="1.3.6.1.4.1.26376.99.1.3" status="current">
      <description>
          A list of input.
      </description>
      <row name="inputEntry" oid="1.3.6.1.4.1.26376.99.1.3.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular input.
        </description>
        <column name="inputVoltage" oid="1.3.6.1.4.1.26376.99.1.3.1.1" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input voltage (0.1V). I.e. 1212 (121.2V).
          </description>
        </column>
        <column name="inputVoltageMaximum" oid="1.3.6.1.4.1.26376.99.1.3.1.2" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum incoming voltage seen (0.1V). I.e. 1300.
          </description>
        </column>
        <column name="inputVoltageMinimum" oid="1.3.6.1.4.1.26376.99.1.3.1.3" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum incoming voltage seen (0.1V). I.e. 1000.
          </description>
        </column>
        <column name="inputVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.4" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal input voltage (0.1V). I.e. 1200.
          </description>
        </column>
        <column name="inputVoltageExtended" oid="1.3.6.1.4.1.26376.99.1.3.1.5" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Extended input voltage range. I.e. no.
          </description>
        </column>
        <column name="inputTransferReason" oid="1.3.6.1.4.1.26376.99.1.3.1.6" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Reason for last transfer to battery (* opaque). I.e. T.
          </description>
        </column>
        <column name="inputTransferLow" oid="1.3.6.1.4.1.26376.99.1.3.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Low voltage transfer point. I.e. 91.
          </description>
        </column>
        <column name="inputTransferHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.8" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              High voltage transfer point. I.e. 132.
          </description>
        </column>
        <column name="inputTransferLowMin" oid="1.3.6.1.4.1.26376.99.1.3.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              smallest settable low voltage transfer point. I.e. 85.
          </description>
        </column>
        <column name="inputTransferLowMax" oid="1.3.6.1.4.1.26376.99.1.3.1.10" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              greatest settable low voltage transfer point. I.e. 95.
          </description>
        </column>
        <column name="inputTransferHighMin" oid="1.3.6.1.4.1.26376.99.1.3.1.11" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              smallest settable high voltage transfer point. I.e. 131.
          </description>
        </column>
        <column name="inputTransferHighMax" oid="1.3.6.1.4.1.26376.99.1.3.1.12" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              greatest settable high voltage transfer point. I.e. 136.
          </description>
        </column>
        <column name="inputSensitivity" oid="1.3.6.1.4.1.26376.99.1.3.1.13" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input power sensitivity. I.e. H (high).
          </description>
        </column>
        <column name="inputQuality" oid="1.3.6.1.4.1.26376.99.1.3.1.14" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input power quality (* opaque). I.e. FF.
          </description>
        </column>
        <column name="inputCurrent" oid="1.3.6.1.4.1.26376.99.1.3.1.15" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input current (0.01 A). I.e. 425 (4.25A).
          </description>
        </column>
        <column name="inputCurrentNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.16" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal input current (0.01 A). I.e. 500 (5 A).
          </description>
        </column>
        <column name="inputFrequency" oid="1.3.6.1.4.1.26376.99.1.3.1.17" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input line frequency (0.1 Hz). I.e. 602 (60.2 Hz).
          </description>
        </column>
        <column name="inputFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.18" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal input line frequency (0.1 Hz). I.e. 600.
          </description>
        </column>
        <column name="inputFrequencyLow" oid="1.3.6.1.4.1.26376.99.1.3.1.19" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input line frequency low (0.1 Hz). I.e. 470.
          </description>
        </column>
        <column name="inputFrequencyHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.20" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Input line frequency high (0.1 Hz). I.e. 630.
          </description>
        </column>
        <column name="inputFrequencyExtended" oid="1.3.6.1.4.1.26376.99.1.3.1.21" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Extended input frequency range. I.e. no.
          </description>
        </column>
        <column name="inputTransferBoostLow" oid="1.3.6.1.4.1.26376.99.1.3.1.22" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Low voltage boosting transfer point. I.e. 190.
          </description>
        </column>
        <column name="inputTransferBoostHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.23" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              High voltage boosting transfer point. I.e. 210.
          </description>
        </column>
        <column name="inputTransferTrimLow" oid="1.3.6.1.4.1.26376.99.1.3.1.24" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Low voltage trimming transfer point. I.e. 230.
          </description>
        </column>
        <column name="inputTransferTrimHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.25" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              High voltage trimming transfer point. I.e. 240.
          </description>
        </column>
        <column name="inputPhases" oid="1.3.6.1.4.1.26376.99.1.3.1.26" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="1" max="1"/>
              <range min="3" max="3"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              (3 for three-phase, absent or 1 for 1 phase). I.e. 3
          </description>
        </column>
      </row>
    </table>
    <table name="outputTable" oid="1.3.6.1.4.1.26376.99.1.4" status="current">
      <description>
          A list of output.
      </description>
      <row name="outputEntry" oid="1.3.6.1.4.1.26376.99.1.4.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular output.
        </description>
        <column name="outputVoltage" oid="1.3.6.1.4.1.26376.99.1.4.1.1" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Output voltage (0.1 V). I.e. 120.9.
          </description>
        </column>
        <column name="outputVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.2" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal output voltage (0.1 V). I.e. 120.
          </description>
        </column>
        <column name="outputFrequency" oid="1.3.6.1.4.1.26376.99.1.4.1.3" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Output frequency (0.1 Hz). I.e. 599 (59.9 Hz).
          </description>
        </column>
        <column name="outputFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.4" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal output frequency (0.1 Hz). I.e. 60.
          </description>
        </column>
        <column name="outputCurrent" oid="1.3.6.1.4.1.26376.99.1.4.1.5" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Output current (0.01 A). I.e. 425 (42.5 A).
          </description>
        </column>
        <column name="outputCurrentNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.6" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal output current (0.01 A). I.e. 500 (5 A).
          </description>
        </column>
        <column name="outputPhases" oid="1.3.6.1.4.1.26376.99.1.4.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="1" max="1"/>
              <range min="3" max="3"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              (3 for three-phase, absent or 1 for 1 phase). I.e. 3
          </description>
        </column>
      </row>
    </table>
    <table name="batteryTable" oid="1.3.6.1.4.1.26376.99.1.5" status="current">
      <description>
          A list of battery.
      </description>
      <row name="batteryEntry" oid="1.3.6.1.4.1.26376.99.1.5.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular battery.
        </description>
        <column name="batteryCharge" oid="1.3.6.1.4.1.26376.99.1.5.1.1" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery charge (0.1 percent). I.e. 1000 (100%).
          </description>
        </column>
        <column name="batteryChargeLow" oid="1.3.6.1.4.1.26376.99.1.5.1.2" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Remaining battery level when UPS switches to LB (0.1 percent). I.e. 20.
          </description>
        </column>
        <column name="batteryChargeRestart" oid="1.3.6.1.4.1.26376.99.1.5.1.3" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum battery level for UPS restart after power-off (0.1 percent). I.e. 20.
          </description>
        </column>
        <column name="batteryChargeWarning" oid="1.3.6.1.4.1.26376.99.1.5.1.4" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery level when UPS switches to 'Warning' state (0.1 percent). I.e. 50.
          </description>
        </column>
        <column name="batteryVoltage" oid="1.3.6.1.4.1.26376.99.1.5.1.5" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery voltage (0.01V). I.e. 2484 (24.84 V).
          </description>
        </column>
        <column name="batteryCapacity" oid="1.3.6.1.4.1.26376.99.1.5.1.6" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery capacity (0.1 Ah). I.e. 72 (7.2 Ah).
          </description>
        </column>
        <column name="batteryCurrent" oid="1.3.6.1.4.1.26376.99.1.5.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery current (0.01 A). I.e. 119 (1.19 A).
          </description>
        </column>
        <column name="batteryTemperature" oid="1.3.6.1.4.1.26376.99.1.5.1.8" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery temperature (0.1 degrees C). I.e. 507 (50.7oC).
          </description>
        </column>
        <column name="batteryVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.5.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal battery voltage (0.01 V). I.e. 024.
          </description>
        </column>
        <column name="batteryRuntime" oid="1.3.6.1.4.1.26376.99.1.5.1.10" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery runtime (seconds) Remaining battery runtime. I.e. 1080.
          </description>
        </column>
        <column name="batteryRuntimeLow" oid="1.3.6.1.4.1.26376.99.1.5.1.11" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              when UPS switches to LB (seconds). I.e. 180.
          </description>
        </column>
        <column name="batteryAlarmThreshold" oid="1.3.6.1.4.1.26376.99.1.5.1.12" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery alarm threshold. I.e. 0 (immediate).
          </description>
        </column>
        <column name="batteryDate" oid="1.3.6.1.4.1.26376.99.1.5.1.13" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery change date (opaque string). I.e. 11/14/00.
          </description>
        </column>
        <column name="batteryMfrDate" oid="1.3.6.1.4.1.26376.99.1.5.1.14" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery manufacturing date (opaque string). I.e. 2005/04/02.
          </description>
        </column>
        <column name="batteryPacks" oid="1.3.6.1.4.1.26376.99.1.5.1.15" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Number of battery packs. I.e. 001.
          </description>
        </column>
        <column name="batteryPacksBad" oid="1.3.6.1.4.1.26376.99.1.5.1.16" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Number of bad battery packs. I.e. 000.
          </description>
        </column>
        <column name="batteryType" oid="1.3.6.1.4.1.26376.99.1.5.1.17" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Battery chemistry (opaque string). I.e. PbAc.
          </description>
        </column>
        <column name="batteryProtection" oid="1.3.6.1.4.1.26376.99.1.5.1.18" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Prevent deep discharge of battery. I.e. yes.
          </description>
        </column>
        <column name="batteryEnergysave" oid="1.3.6.1.4.1.26376.99.1.5.1.19" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Switch off when running on battery and no/low load. I.e. no.
          </description>
        </column>
      </row>
    </table>
    <table name="ambientTable" oid="1.3.6.1.4.1.26376.99.1.6" status="current">
      <description>
          A list of ambient.
      </description>
      <row name="ambientEntry" oid="1.3.6.1.4.1.26376.99.1.6.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular ambient.
        </description>
        <column name="ambientTemperature" oid="1.3.6.1.4.1.26376.99.1.6.1.1" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Ambient temperature (0.1 degrees C). I.e. 25.40.
          </description>
        </column>
        <column name="ambientTemperatureAlarm" oid="1.3.6.1.4.1.26376.99.1.6.1.2" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="disabled" number="0"/>
              <namednumber name="enabled" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Temperature alarm (enabled/disabled). I.e. enabled.
          </description>
        </column>
        <column name="ambientTemperatureHigh" oid="1.3.6.1.4.1.26376.99.1.6.1.3" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Temperature threshold high (degrees C). I.e. 40.
          </description>
        </column>
        <column name="ambientTemperatureLow" oid="1.3.6.1.4.1.26376.99.1.6.1.4" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Temperature threshold low (degrees C). I.e. 5.
          </description>
        </column>
        <column name="ambientTemperatureMaximum" oid="1.3.6.1.4.1.26376.99.1.6.1.5" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum temperature seen (0.1 degrees C). I.e. 37.6.
          </description>
        </column>
        <column name="ambientTemperatureMinimum" oid="1.3.6.1.4.1.26376.99.1.6.1.6" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="-2730" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum temperature seen (0.1 degrees C). I.e. 18.1.
          </description>
        </column>
        <column name="ambientHumidity" oid="1.3.6.1.4.1.26376.99.1.6.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Ambient relative humidity (0.1 percent). I.e. 388 (38.8%).
          </description>
        </column>
        <column name="ambientHumidityAlarm" oid="1.3.6.1.4.1.26376.99.1.6.1.8" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="disabled" number="0"/>
              <namednumber name="enabled" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Relative humidity alarm (enabled/disabled). I.e. enabled.
          </description>
        </column>
        <column name="ambientHumidityHigh" oid="1.3.6.1.4.1.26376.99.1.6.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Relative humidity threshold high (percent). I.e. 80.
          </description>
        </column>
        <column name="ambientHumidityLow" oid="1.3.6.1.4.1.26376.99.1.6.1.10" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Relative humidity threshold high (percent). I.e. 10.
          </description>
        </column>
        <column name="ambientHumidityMaximum" oid="1.3.6.1.4.1.26376.99.1.6.1.11" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum relative humidity seen (percent). I.e. 60.
          </description>
        </column>
        <column name="ambientHumidityMinimum" oid="1.3.6.1.4.1.26376.99.1.6.1.12" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="1000"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum relative humidity seen (percent). I.e. 13.
          </description>
        </column>
      </row>
    </table>
    <table name="outletTable" oid="1.3.6.1.4.1.26376.99.1.7" status="current">
      <description>
          A list of outlet.
      </description>
      <row name="outletEntry" oid="1.3.6.1.4.1.26376.99.1.7.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
          <index module="NUT-MIB" name="outletIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular outlet.
        </description>
        <column name="outletIndex" oid="1.3.6.1.4.1.26376.99.1.7.1.1" status="current">
          <syntax>
            <type module="NUT-MIB" name="OutletIndexType"/>
          </syntax>
          <access>noaccess</access>
          <description>
              A unique value, greater than or equal to zero, for each outlet. It stands for the outlet index.
              A special case is 0 which represents the whole set of outlets of the device.
          </description>
        </column>
        <column name="outletId" oid="1.3.6.1.4.1.26376.99.1.7.1.2" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Outlet system identifier (opaque string). I.e. 1.
          </description>
        </column>
        <column name="outletDesc" oid="1.3.6.1.4.1.26376.99.1.7.1.3" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Outlet description (opaque string). I.e. Main outlet.
          </description>
        </column>
        <column name="outletSwitch" oid="1.3.6.1.4.1.26376.99.1.7.1.4" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="off" number="0"/>
              <namednumber name="on" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Outlet switch control (on/off). I.e. on.
          </description>
        </column>
        <column name="outletStatus" oid="1.3.6.1.4.1.26376.99.1.7.1.5" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="off" number="0"/>
              <namednumber name="on" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Outlet switch status (on/off). I.e. on.
          </description>
        </column>
        <column name="outletSwitchable" oid="1.3.6.1.4.1.26376.99.1.7.1.6" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="no" number="0"/>
              <namednumber name="yes" number="1"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Outlet switch ability (yes/no). I.e. yes.
          </description>
        </column>
        <column name="outletAutoswitchChargeLow" oid="1.3.6.1.4.1.26376.99.1.7.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Remaining battery level to power off this outlet (percent). I.e. 80.
          </description>
        </column>
        <column name="outletDelayShutdown" oid="1.3.6.1.4.1.26376.99.1.7.1.8" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before shutting down this outlet (seconds). I.e. 180.
          </description>
        </column>
        <column name="outletDelayStart" oid="1.3.6.1.4.1.26376.99.1.7.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before restarting this outlet (seconds). I.e. 120.
          </description>
        </column>
        <column name="outletCurrent" oid="1.3.6.1.4.1.26376.99.1.7.1.10" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current (0.01 A). I.e. 19 (0.19 A).
          </description>
        </column>
        <column name="outletCurrentMaximum" oid="1.3.6.1.4.1.26376.99.1.7.1.11" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum seen current (0.01 A). I.e. 56 (0.56 A).
          </description>
        </column>
        <column name="outletRealpower" oid="1.3.6.1.4.1.26376.99.1.7.1.12" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current value of real power (W). I.e. 28.
          </description>
        </column>
        <column name="outletVoltage" oid="1.3.6.1.4.1.26376.99.1.7.1.13" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Voltage (0.1 V). I.e. 2470 (247 V).
          </description>
        </column>
        <column name="outletPowerfactor" oid="1.3.6.1.4.1.26376.99.1.7.1.14" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Power Factor (dimensionless value between 0 and 1, multiplied by 100). I.e. 85 (0.85).
          </description>
        </column>
        <column name="outletCrestfactor" oid="1.3.6.1.4.1.26376.99.1.7.1.15" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Crest Factor (dimensionless, equal to or greater than 1, multiplied by 100). I.e. 141 (1.41).
          </description>
        </column>
        <column name="outletPower" oid="1.3.6.1.4.1.26376.99.1.7.1.16" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Apparent power (VA). I.e. 46.
          </description>
        </column>
      </row>
    </table>
    <table name="driverTable" oid="1.3.6.1.4.1.26376.99.1.8" status="current">
      <description>
          A list of driver.
      </description>
      <row name="driverEntry" oid="1.3.6.1.4.1.26376.99.1.8.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular driver.
        </description>
        <column name="driverName" oid="1.3.6.1.4.1.26376.99.1.8.1.1" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Driver name. I.e. usbhid-ups.
          </description>
        </column>
        <column name="driverVersion" oid="1.3.6.1.4.1.26376.99.1.8.1.2" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Driver version (NUT release). I.e. X.Y.Z.
          </description>
        </column>
        <column name="driverVersionInternal" oid="1.3.6.1.4.1.26376.99.1.8.1.3" status="current">
          <syntax>
            <typedef basetype="OctetString">
              <parent module="SNMPv2-TC" name="DisplayString"/>
              <range min="0" max="255"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Internal driver version (if tracked separately). I.e. 1.23.45.
          </description>
        </column>
      </row>
    </table>
    <node name="serverObjects" oid="1.3.6.1.4.1.26376.99.1.9">
    </node>
    <scalar name="serverInfo" oid="1.3.6.1.4.1.26376.99.1.9.1" status="current">
      <syntax>
        <typedef basetype="OctetString">
          <parent module="SNMPv2-TC" name="DisplayString"/>
          <range min="0" max="255"/>
        </typedef>
      </syntax>
      <access>readonly</access>
      <description>
          Server information. I.e. Network UPS Tools upsd vX.Y.Z - http://www.networkupstools.org/.
      </description>
    </scalar>
    <scalar name="serverVersion" oid="1.3.6.1.4.1.26376.99.1.9.2" status="current">
      <syntax>
        <typedef basetype="OctetString">
          <parent module="SNMPv2-TC" name="DisplayString"/>
          <range min="0" max="255"/>
        </typedef>
      </syntax>
      <access>readonly</access>
      <description>
          Server version. I.e. X.Y.Z.
      </description>
    </scalar>
    <table name="threephaseTable" oid="1.3.6.1.4.1.26376.99.1.10" status="current">
      <description>
          A list of driver.
      </description>
      <row name="threephaseEntry" oid="1.3.6.1.4.1.26376.99.1.10.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="deviceIndex"/>
          <index module="NUT-MIB" name="threephaseDomain"/>
          <index module="NUT-MIB" name="threephaseSubdomain"/>
          <index module="NUT-MIB" name="threephaseContext"/>
        </linkage>
        <description>
            An entry containing information about a particular driver.
        </description>
        <column name="threephaseDomain" oid="1.3.6.1.4.1.26376.99.1.10.1.1" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="input" number="1"/>
              <namednumber name="output" number="2"/>
            </typedef>
          </syntax>
          <access>noaccess</access>
          <description>
              In a three-phased device, this type defines if the measure is about the
              input or output.
          </description>
        </column>
        <column name="threephaseSubdomain" oid="1.3.6.1.4.1.26376.99.1.10.1.2" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="mains" number="1"/>
              <namednumber name="bypass" number="2"/>
              <namednumber name="servicebypass" number="3"/>
              <namednumber name="load" number="4"/>
              <namednumber name="inverter" number="5"/>
            </typedef>
          </syntax>
          <access>noaccess</access>
          <description>
              In a three-phased device, in combination with DomainType, this type completes
              the measure context. 'mains' (input.mains.) is only for input and is equals to 'input.'.
              'load' (output.load.) is only for output and is equals to 'output.'. inverter is also
              only for output.
          </description>
        </column>
        <column name="threephaseContext" oid="1.3.6.1.4.1.26376.99.1.10.1.3" status="current">
          <syntax>
            <typedef basetype="Enumeration">
              <namednumber name="none" number="0"/>
              <namednumber name="n" number="1"/>
              <namednumber name="l1" number="2"/>
              <namednumber name="l2" number="3"/>
              <namednumber name="l3" number="4"/>
              <namednumber name="l1n" number="5"/>
              <namednumber name="l2n" number="6"/>
              <namednumber name="l3n" number="7"/>
              <namednumber name="l1l2" number="8"/>
              <namednumber name="l2l3" number="9"/>
              <namednumber name="l3l1" number="10"/>
            </typedef>
          </syntax>
          <access>noaccess</access>
          <description>
              In a three-phased device, the naming scheme becomes DOMAIN.CONTEXT.SPEC when in
              three-phase mode. Example: input.L1.current. 'none' means the absence of context,
              for frequency related measures and aggregated/averaged ones
          </description>
        </column>
        <column name="threephaseCurrent" oid="1.3.6.1.4.1.26376.99.1.10.1.4" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current (0.01 A). I.e. 19 (0.19 A).
          </description>
        </column>
        <column name="threephaseCurrentMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.5" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum seen current (0.01 A). I.e. 56 (0.56 A).
          </description>
        </column>
        <column name="threephaseCurrentMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.6" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum seen current (0.01 A). I.e. 56 (0.56 A).
          </description>
        </column>
        <column name="threephaseCurrentPeak" oid="1.3.6.1.4.1.26376.99.1.10.1.7" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Peak current (0.01 A). I.e. 56 (0.56 A).
          </description>
        </column>
        <column name="threephaseVoltage" oid="1.3.6.1.4.1.26376.99.1.10.1.8" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Voltage (0.1 V). I.e. 2470 (247 V).
          </description>
        </column>
        <column name="threephaseVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.10.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal voltage (0.1 V). I.e. 2470 (247 V).
          </description>
        </column>
        <column name="threephaseVoltageMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.10" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum seen voltage (0.1 V). I.e. 2470 (247 V).
          </description>
        </column>
        <column name="threephaseVoltageMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.11" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum seen voltage (0.1 V). I.e. 2470 (247 V).
          </description>
        </column>
        <column name="threephasePower" oid="1.3.6.1.4.1.26376.99.1.10.1.12" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Apparent power (VA). I.e. 46.
          </description>
        </column>
        <column name="threephasePowerMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.13" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Maximum seen apparent power (VA). I.e. 46.
          </description>
        </column>
        <column name="threephasePowerMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.14" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Minimum seen apparent power (VA). I.e. 46.
          </description>
        </column>
        <column name="threephasePowerPercent" oid="1.3.6.1.4.1.26376.99.1.10.1.15" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Percentage of apparent power related to maximum load (percent). I.e. 023.
          </description>
        </column>
        <column name="threephasePowerPercentMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.16" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Max seen percentage of apparent power (percent). I.e. 023.
          </description>
        </column>
        <column name="threephasePowerPercentMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.17" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Min seen percentage of apparent power (percent). I.e. 023.
          </description>
        </column>
        <column name="threephaseRealpower" oid="1.3.6.1.4.1.26376.99.1.10.1.18" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Current value of real power (W). I.e. 28.
          </description>
        </column>
        <column name="threephasePowerfactor" oid="1.3.6.1.4.1.26376.99.1.10.1.19" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="0" max="100"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Power Factor (dimensionless value between 0 and 1, multiplied by 100). I.e. 85 (0.85).
          </description>
        </column>
        <column name="threephaseCrestfactor" oid="1.3.6.1.4.1.26376.99.1.10.1.20" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="HundredthInteger32"/>
              <range min="1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Crest Factor (dimensionless, equal to or greater than 1, multiplied by 100). I.e. 141 (1.41).
          </description>
        </column>
        <column name="threephaseFrequency" oid="1.3.6.1.4.1.26376.99.1.10.1.21" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Frequency (0.1 Hz). I.e. 602 (60.2 Hz).
          </description>
        </column>
        <column name="threephaseFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.10.1.22" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <parent module="NUT-MIB" name="TenthInteger32"/>
              <range min="0" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Nominal frequency (0.1 Hz). I.e. 600.
          </description>
        </column>
      </row>
    </table>
    <node name="nutConformance" oid="1.3.6.1.4.1.26376.99.2">
    </node>
    <node name="nutGroups" oid="1.3.6.1.4.1.26376.99.2.1">
    </node>
    <node name="nutCompliances" oid="1.3.6.1.4.1.26376.99.2.2">
    </node>
  </nodes>

  <groups>
    <group name="nutDeviceGroup" oid="1.3.6.1.4.1.26376.99.2.1.1" status="current">
      <members>
        <member module="NUT-MIB" name="deviceName"/>
        <member module="NUT-MIB" name="deviceDesc"/>
        <member module="NUT-MIB" name="deviceModel"/>
        <member module="NUT-MIB" name="deviceMfr"/>
        <member module="NUT-MIB" name="deviceSerial"/>
        <member module="NUT-MIB" name="deviceType"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a device
      </description>
    </group>
    <group name="nutUpsGroup" oid="1.3.6.1.4.1.26376.99.2.1.2" status="current">
      <members>
        <member module="NUT-MIB" name="upsStatus"/>
        <member module="NUT-MIB" name="upsAlarm"/>
        <member module="NUT-MIB" name="upsTime"/>
        <member module="NUT-MIB" name="upsDate"/>
        <member module="NUT-MIB" name="upsModel"/>
        <member module="NUT-MIB" name="upsMfr"/>
        <member module="NUT-MIB" name="upsMfrDate"/>
        <member module="NUT-MIB" name="upsSerial"/>
        <member module="NUT-MIB" name="upsVendorid"/>
        <member module="NUT-MIB" name="upsProductid"/>
        <member module="NUT-MIB" name="upsFirmware"/>
        <member module="NUT-MIB" name="upsFirmwareAux"/>
        <member module="NUT-MIB" name="upsTemperature"/>
        <member module="NUT-MIB" name="upsLoad"/>
        <member module="NUT-MIB" name="upsLoadHigh"/>
        <member module="NUT-MIB" name="upsId"/>
        <member module="NUT-MIB" name="upsDelayStart"/>
        <member module="NUT-MIB" name="upsDelayReboot"/>
        <member module="NUT-MIB" name="upsDelayShutdown"/>
        <member module="NUT-MIB" name="upsTimerStart"/>
        <member module="NUT-MIB" name="upsTimerReboot"/>
        <member module="NUT-MIB" name="upsTimerShutdown"/>
        <member module="NUT-MIB" name="upsTestInterval"/>
        <member module="NUT-MIB" name="upsTestResult"/>
        <member module="NUT-MIB" name="upsDisplayLanguage"/>
        <member module="NUT-MIB" name="upsContacts"/>
        <member module="NUT-MIB" name="upsEfficiency"/>
        <member module="NUT-MIB" name="upsPower"/>
        <member module="NUT-MIB" name="upsPowerNominal"/>
        <member module="NUT-MIB" name="upsRealpower"/>
        <member module="NUT-MIB" name="upsRealpowerNominal"/>
        <member module="NUT-MIB" name="upsBeeperStatus"/>
        <member module="NUT-MIB" name="upsType"/>
        <member module="NUT-MIB" name="upsWatchdogStatus"/>
        <member module="NUT-MIB" name="upsStartAuto"/>
        <member module="NUT-MIB" name="upsStartBattery"/>
        <member module="NUT-MIB" name="upsStartReboot"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a device
      </description>
    </group>
    <group name="nutInputGroup" oid="1.3.6.1.4.1.26376.99.2.1.3" status="current">
      <members>
        <member module="NUT-MIB" name="inputVoltage"/>
        <member module="NUT-MIB" name="inputVoltageMaximum"/>
        <member module="NUT-MIB" name="inputVoltageMinimum"/>
        <member module="NUT-MIB" name="inputVoltageNominal"/>
        <member module="NUT-MIB" name="inputVoltageExtended"/>
        <member module="NUT-MIB" name="inputTransferReason"/>
        <member module="NUT-MIB" name="inputTransferLow"/>
        <member module="NUT-MIB" name="inputTransferHigh"/>
        <member module="NUT-MIB" name="inputTransferLowMin"/>
        <member module="NUT-MIB" name="inputTransferLowMax"/>
        <member module="NUT-MIB" name="inputTransferHighMin"/>
        <member module="NUT-MIB" name="inputTransferHighMax"/>
        <member module="NUT-MIB" name="inputSensitivity"/>
        <member module="NUT-MIB" name="inputQuality"/>
        <member module="NUT-MIB" name="inputCurrent"/>
        <member module="NUT-MIB" name="inputCurrentNominal"/>
        <member module="NUT-MIB" name="inputFrequency"/>
        <member module="NUT-MIB" name="inputFrequencyNominal"/>
        <member module="NUT-MIB" name="inputFrequencyLow"/>
        <member module="NUT-MIB" name="inputFrequencyHigh"/>
        <member module="NUT-MIB" name="inputFrequencyExtended"/>
        <member module="NUT-MIB" name="inputTransferBoostLow"/>
        <member module="NUT-MIB" name="inputTransferBoostHigh"/>
        <member module="NUT-MIB" name="inputTransferTrimLow"/>
        <member module="NUT-MIB" name="inputTransferTrimHigh"/>
        <member module="NUT-MIB" name="inputPhases"/>
      </members>
      <description>
          A collection of objects providing information specific to
          an input of a device
      </description>
    </group>
    <group name="nutOututGroup" oid="1.3.6.1.4.1.26376.99.2.1.4" status="current">
      <members>
        <member module="NUT-MIB" name="outputVoltage"/>
        <member module="NUT-MIB" name="outputVoltageNominal"/>
        <member module="NUT-MIB" name="outputFrequency"/>
        <member module="NUT-MIB" name="outputFrequencyNominal"/>
        <member module="NUT-MIB" name="outputCurrent"/>
        <member module="NUT-MIB" name="outputCurrentNominal"/>
        <member module="NUT-MIB" name="outputPhases"/>
      </members>
      <description>
          A collection of objects providing information specific to
          an output of a device
      </description>
    </group>
    <group name="nutBatteryGroup" oid="1.3.6.1.4.1.26376.99.2.1.5" status="current">
      <members>
        <member module="NUT-MIB" name="batteryCharge"/>
        <member module="NUT-MIB" name="batteryChargeLow"/>
        <member module="NUT-MIB" name="batteryChargeRestart"/>
        <member module="NUT-MIB" name="batteryChargeWarning"/>
        <member module="NUT-MIB" name="batteryVoltage"/>
        <member module="NUT-MIB" name="batteryCapacity"/>
        <member module="NUT-MIB" name="batteryCurrent"/>
        <member module="NUT-MIB" name="batteryTemperature"/>
        <member module="NUT-MIB" name="batteryVoltageNominal"/>
        <member module="NUT-MIB" name="batteryRuntime"/>
        <member module="NUT-MIB" name="batteryRuntimeLow"/>
        <member module="NUT-MIB" name="batteryAlarmThreshold"/>
        <member module="NUT-MIB" name="batteryDate"/>
        <member module="NUT-MIB" name="batteryMfrDate"/>
        <member module="NUT-MIB" name="batteryPacks"/>
        <member module="NUT-MIB" name="batteryPacksBad"/>
        <member module="NUT-MIB" name="batteryType"/>
        <member module="NUT-MIB" name="batteryProtection"/>
        <member module="NUT-MIB" name="batteryEnergysave"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a baterry of a device
      </description>
    </group>
    <group name="nutAmbientGroup" oid="1.3.6.1.4.1.26376.99.2.1.6" status="current">
      <members>
        <member module="NUT-MIB" name="ambientTemperature"/>
        <member module="NUT-MIB" name="ambientTemperatureAlarm"/>
        <member module="NUT-MIB" name="ambientTemperatureHigh"/>
        <member module="NUT-MIB" name="ambientTemperatureLow"/>
        <member module="NUT-MIB" name="ambientTemperatureMaximum"/>
        <member module="NUT-MIB" name="ambientTemperatureMinimum"/>
        <member module="NUT-MIB" name="ambientHumidity"/>
        <member module="NUT-MIB" name="ambientHumidityAlarm"/>
        <member module="NUT-MIB" name="ambientHumidityHigh"/>
        <member module="NUT-MIB" name="ambientHumidityLow"/>
        <member module="NUT-MIB" name="ambientHumidityMaximum"/>
        <member module="NUT-MIB" name="ambientHumidityMinimum"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the ambient of a device
      </description>
    </group>
    <group name="nutOutletGroup" oid="1.3.6.1.4.1.26376.99.2.1.7" status="current">
      <members>
        <member module="NUT-MIB" name="outletId"/>
        <member module="NUT-MIB" name="outletDesc"/>
        <member module="NUT-MIB" name="outletSwitch"/>
        <member module="NUT-MIB" name="outletStatus"/>
        <member module="NUT-MIB" name="outletSwitchable"/>
        <member module="NUT-MIB" name="outletAutoswitchChargeLow"/>
        <member module="NUT-MIB" name="outletDelayShutdown"/>
        <member module="NUT-MIB" name="outletDelayStart"/>
        <member module="NUT-MIB" name="outletCurrent"/>
        <member module="NUT-MIB" name="outletCurrentMaximum"/>
        <member module="NUT-MIB" name="outletRealpower"/>
        <member module="NUT-MIB" name="outletVoltage"/>
        <member module="NUT-MIB" name="outletPowerfactor"/>
        <member module="NUT-MIB" name="outletCrestfactor"/>
        <member module="NUT-MIB" name="outletPower"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a outlet of a device
      </description>
    </group>
    <group name="nutDriverGroup" oid="1.3.6.1.4.1.26376.99.2.1.8" status="current">
      <members>
        <member module="NUT-MIB" name="driverName"/>
        <member module="NUT-MIB" name="driverVersion"/>
        <member module="NUT-MIB" name="driverVersionInternal"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the driver of a device
      </description>
    </group>
    <group name="nutServerGroup" oid="1.3.6.1.4.1.26376.99.2.1.9" status="current">
      <members>
        <member module="NUT-MIB" name="serverInfo"/>
        <member module="NUT-MIB" name="serverVersion"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the server
      </description>
    </group>
    <group name="nutThreephaseGroup" oid="1.3.6.1.4.1.26376.99.2.1.10" status="current">
      <members>
        <member module="NUT-MIB" name="threephaseCurrent"/>
        <member module="NUT-MIB" name="threephaseCurrentMaximum"/>
        <member module="NUT-MIB" name="threephaseCurrentMinimum"/>
        <member module="NUT-MIB" name="threephaseCurrentPeak"/>
        <member module="NUT-MIB" name="threephaseVoltage"/>
        <member module="NUT-MIB" name="threephaseVoltageNominal"/>
        <member module="NUT-MIB" name="threephaseVoltageMaximum"/>
        <member module="NUT-MIB" name="threephaseVoltageMinimum"/>
        <member module="NUT-MIB" name="threephasePower"/>
        <member module="NUT-MIB" name="threephasePowerMaximum"/>
        <member module="NUT-MIB" name="threephasePowerMinimum"/>
        <member module="NUT-MIB" name="threephasePowerPercent"/>
        <member module="NUT-MIB" name="threephasePowerPercentMaximum"/>
        <member module="NUT-MIB" name="threephasePowerPercentMinimum"/>
        <member module="NUT-MIB" name="threephaseRealpower"/>
        <member module="NUT-MIB" name="threephasePowerfactor"/>
        <member module="NUT-MIB" name="threephaseCrestfactor"/>
        <member module="NUT-MIB" name="threephaseFrequency"/>
        <member module="NUT-MIB" name="threephaseFrequencyNominal"/>
      </members>
      <description>
          A collection of objects providing information specific to
          three-phased devices in three-phase mode
      </description>
    </group>
  </groups>

  <compliances>
    <compliance name="nutCompliance1" oid="1.3.6.1.4.1.26376.99.2.2.1" status="current">
      <description>
          The compliance statement for NUT devices.
      </description>
      <requires>
        <mandatory module="NUT-MIB" name="nutServerGroup"/>
        <option module="NUT-MIB" name="nutDeviceGroup">
          <description>
              A collection of objects providing information specific to
              a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutUpsGroup">
          <description>
              A collection of objects providing information specific to
              a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutInputGroup">
          <description>
              A collection of objects providing information specific to
              an input of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutOututGroup">
          <description>
              A collection of objects providing information specific to
              an output of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutBatteryGroup">
          <description>
              A collection of objects providing information specific to
              a baterry of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutAmbientGroup">
          <description>
              A collection of objects providing information specific to
              the ambient of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutOutletGroup">
          <description>
              A collection of objects providing information specific to
              a outlet of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutDriverGroup">
          <description>
              A collection of objects providing information specific to
              the driver of a device
          </description>
        </option>
        <option module="NUT-MIB" name="nutServerGroup">
          <description>
              A collection of objects providing information specific to
              the server
          </description>
        </option>
        <option module="NUT-MIB" name="nutThreephaseGroup">
          <description>
              A collection of objects providing information specific to
              three-phased devices in three-phase mode
          </description>
        </option>
      </requires>
    </compliance>
  </compliances>

</smi>
