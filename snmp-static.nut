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
# How to use:
#
# TODO: get a IANA number for NUT
#
# /etc/snmp/snmpd.conf
# pass_persist .1.3.6.1.4.1.26376.99 /my/path/to/snmp.nut
#
#
# What is missing:
# - I ignored the driver parameters.
#
# What I found of docs problem:
# - Missing field: driver.version.data
# - Wrong description of power.minimum     Maximum seen apparent power (VA)
#
# MAYBE
# - use set for ups comands like load.off
#
require "thread"
#require "snmppass"
#
#
#

if RUBY_VERSION<="1.8.5"
require 'rexml/document'
class REXML::Elements
    def collect(*args)
        res=[]
	each(*args) {|*el|
            res << yield(*el)
        }
        res
    end
end
end

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
                raise "Type cannot be nil" if not type
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
                roid=self.oid2roid(oid) if (oid<=>self.oid) >= 0
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
                (roid,value,type)=@callback.call OP_GET, roid
                return Node.new(self.roid2oid(roid), type, value) if value
                return nil
            end

            def getnext(oid)
                roid=[]
                roid=self.oid2roid(oid) if (oid<=>self.oid)>=0
                (roid,value,type)=@callback.call OP_GETNEXT, roid
                return Node.new(self.roid2oid(roid), type, value) if value
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
        def chat
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
            #$DEBUG.puts "Registering #{SNMPPass.num2oid(node.oid)} with #{node}"
            @fields[node.oid]=node
        end
        
        def self.read_arguments(args)
            $DEBUG=File.open("/dev/null","w")
            mode=:chat
            while args.size>0
                case args.first
                when "-d",'--debug'
                    $DEBUG=File.open("/dev/stderr","w")
                    $DEBUG.sync=true
                when "-f",'--filelog'
                    $DEBUG=File.open("/tmp/snmp.log","w")
                    $DEBUG.sync=true
                when "-s","--syslog"
                    $DEBUG.sync=true
                    $DEBUG=IO.popen("logger -t snmp", "w")
                when "-w",'--walk'
                    $DEBUG.puts "Starting walk..."
                    mode=:walk
                when "-h","--help","-?"
                    $stderr.puts <<-EOF
Use:

    [ruby[1.9]] #{$0} [arguments]

Or put in snmpd.conf:

    pass_persist OID [ruby[1.9]] #{$0}

The valid arguments are:

    -d|--debug      Send debug information to $stderr
    -f|--filelog    Send debug information to /tmp/snmp.log
    -s|--syslog     Send debug information to syslog service
    -w|--walk       Simulate a snmp walk (simlar to snmpwalk command)
    -h|--help       Show this help

                    EOF
                    mode=:help
                else
                    if block_given?
                        ok = yield args
                        next if ok
                    end
                    $stderr.puts "Invalid option #{args[0]}. See #{$0} --help"
                    mode=:error
                end
                args.shift
            end
            mode
        end

        def self.start(args,*parameters)
            mode = read_arguments(args)
            begin
                snmp = self.new(*parameters)
                case mode
                when :walk
                    puts snmp.walk
                when :chat
                    snmp.chat
                when :error
                    exit 1
                when :help
                    exit 0
                end
            rescue Exception
                $DEBUG.puts "Program aborted!"
                $DEBUG.puts $!
                $DEBUG.puts $!.backtrace
                exit 1
            end
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
            return if not elements
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
            elsif syntax.elements["type"]
                type=syntax.elements["type"].attributes["name"]
                if @decimals.include?(type)
                    @decimals[nodename]=@decimals[type]
                end
                type=@types[type] if @types.include?(type)
            else
                raise "Unknown object syntax: #{syntax}"
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
                (_, node_column)=roid[0..1]
                node_index=roid[2..-1]
                (column_name,_,column_type)=columns.detect {|(_,column_id,_)| column_id==node_column}
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
                (_,_,column_type)=columns.detect do
                    |(_column_name,_column_id,_column_type)|
                    rows_indexes.detect do
                        |row_indexes|
#                         $DEBUG.puts "Checking for table #{tablename}, column #{column_name} with indexes: #{row_indexes.inspect}"
                        row_column_roid=[1, _column_id] + row_indexes
                        $DEBUG.puts "Looking for next roid #{roid.inspect} X #{row_column_roid.inspect}"
                        if (not roid or roid.empty?) or ((roid <=> row_column_roid) < 0)
                            $DEBUG.puts "Calling #{_column_name}(#{row_indexes.join(",")})"
                            value=self.send(_column_name, *row_indexes)
                            value=format_value(_column_type,_column_name,value) if value
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
            oid=SNMPPass.oid2num(element.attributes["oid"])+[0]
            type=prepare_type(element.elements["syntax"], name)
            add_node(DynamicNode.new(oid,type) { self.send(name) })
        end

        # Starts the program reading the embebed MIB (in xml) from main file
        def self.start_embebedmib(args,*parameters)
            start(args,read_embebedmib,*parameters)
        end

        # Reads the MIB emebeded after the __END__ tag
        def self.read_embebedmib
            `sed -e '1,/^__END__/d' #{$0}`
        end
    end
end
#require "cached_method"
#
#
#
module CachedMethod
    NOCACHE_SUFIX="_nocache"

    def cached(method, args, ttf=@cache_ttf)
        key=[method, args]
        return nil if not @cache or not @cache.include? key
        (result, timestamp)=@cache[key]
        return nil if Time.now-timestamp>ttf
        return result
    end

    def cache(method, result, args)
        key=[method, args]
        @cache=Hash.new if not @cache
        @cache[key]=[result,Time.now]
        result
    end

    def cache_method(method_sym, ttl=nil)
        cached_version=<<-EOM
            alias_method :#{method_sym.to_s + NOCACHE_SUFIX}, :#{method_sym.to_s}
            def #{method_sym.to_s}(*args)
                value = cached(:#{method_sym.to_s}, args #{",#{ttl}" if ttl})
                return value if not value==nil
                return cache(:#{method_sym.to_s},#{method_sym.to_s + NOCACHE_SUFIX}(*args), args)
            end
        EOM
        class_eval cached_version
    end

    attr_accessor :cache_ttf
end
require "orderedhash" if RUBY_VERSION<"1.9"

# I'm the first part specific to NUT. I implement the missing parts that GenericWithMib
# expects to call with upsc command results. I use a lot of metaprogramming for this job.
class Nut < SNMPPass::GenericWithMib

    attr_reader :upsc
    def initialize(mibxml)
        super(mibxml)
        implement_methods
        @upsc=CachedUpsc.new
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
                      nutDeviceTable
                  end
                EOM
            end
            columns.each do
                |(column_name,_,_)|
                if not self.respond_to? column_name
                    $DEBUG.puts "Defining #{column_name}(*indexes)"
                    meta+=<<-EOM
                      def #{column_name}(*indexes)
                          $DEBUG.puts "Running #{column_name}(\#{indexes.inspect})"
                          prop_names=mibname2prop("#{column_name}",*indexes)
                          prop_names=[prop_names] if not prop_names.kind_of? Array
                          nutDeviceIndex=indexes.first
                          prop_names.each { |prop_name|
                                value=upsc[nutDeviceName(nutDeviceIndex),prop_name]
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

    # Maps the mib object names into the upsc property.
    # There is some hacks here in order to match the correct
    # field. It also might receive indexes if the object is inside a table
    def mibname2prop(name,*indexes)
        name.sub!(/^nut/,"")
        #parts=[name.sub(/([a-z]+).*/,"\\1")]
        parts=[]
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
            domain=@enums["nutThreephaseDomain"].invert[threephaseDomain.to_s]
            subdomain=@enums["nutThreephaseSubdomain"].invert[threephaseSubDomain.to_s]
            context=@enums["nutThreephaseContext"].invert[threephaseContext.to_s]
            context=mib_context2upsc_context(context)
            parts[0]=domain
            parts.insert(1,context) if not context=="NONE"
            # HACK: input.mains. is input.
            # HACK: output.load is output.
            parts.insert(1,subdomain) if not ["mains","load"].include?(subdomain)
        end

        return parts.join(".")
    end

    def mib_context2upsc_context(context)
        context.sub(/([0-9])([ln])/,"\\1-\\2").upcase
    end
    def upsc_context2mib_context(context)
        context.sub(/-/,"").downcase
    end


    # Some values can come in a string form like (yes/no,on/off,
    # servicebypass/bypass/...). Convert them using the MIB information
    def parse_property(name,value)
        return value if not @enums.include?(name) or not @enums[name].include?(value)
        @enums[name][value]
    end
  
    SERVER="!"
    def nutServerInfo
        upsc[SERVER,"server.info"]
    end

    def nutServerVersion
        upsc[SERVER,"server.version"]
    end

    # Device table depends on the number of ups returned bu upsc -L
    def nutDeviceTable
        (1..upsc.devices.size).to_a
    end

    def nutDeviceIndex(deviceIndex)
        deviceIndex
    end

    def nutDeviceName(deviceIndex)
        (name,_)=upsc.devices.to_a[deviceIndex-1]
        name
    end

    def nutDeviceDesc(deviceIndex)
        (_,desc)=upsc.devices.to_a[deviceIndex-1]
        desc
    end

    # In order to the the amount of outlets, I need to parse the upsc command
    def nutOutletTable
        idx=nutDeviceTable.collect do
            |dev_id|
            dev_name = nutDeviceName(dev_id)
            upsc.properties(dev_name).
                collect {|prop| prop.split(".") }.
                select {|parts| parts[0] == "outlet" }.
                # HACK: outlet.0 is also outlet.
                collect {|parts| parts[1]="0" if not parts[1] =~ /^[0-9]+$/; parts}.
                collect {|parts| parts[1].to_i }.uniq.sort.
                collect {|outlet_id| [dev_id, outlet_id] }
        end.inject([],:+)
        idx
    end

    def nutOutletIndex(deviceIndex, outletIndex)
        outletIndex
    end

    # In order to the the threephase context and domains avaiable, I need to parse
    # the upsc command
    def nutThreephaseTable
        nutDeviceTable.collect do
            |dev_id|
            indexes_for_device=[]

            isInputThreephase=nutInputPhases(dev_id)=="3"
            isOutputThreephase=nutOutputPhases(dev_id)=="3"
            if isInputThreephase or isOutputThreephase
                # Select only properties about domains
                properties=upsc.properties(nutDeviceName(dev_id)).
                    collect{|prop| prop.split(".")}.
                    select {|prop| @enums["nutThreephaseDomain"].include?(prop.first) }.
                    reject {|prop| prop[1] == "phases"}
                @enums["nutThreephaseDomain"].each do
                    |(domain, domain_id)|
                    domain_properties=properties.select {|prop| prop[0] == domain }
                    next if domain_properties.empty?
                    case domain
                    when "input"
                       absent_subdomain="mains"
                    when "output"
                       absent_subdomain="load"
                    end
                    domain_properties=domain_properties.
                        collect {|prop| @enums["nutThreephaseSubdomain"].include?(prop[1]) ? prop : prop.dup.insert(1,absent_subdomain) }

                    @enums["nutThreephaseSubdomain"].each do
                        |(subdomain, subdomain_id)|
                        subdomain_properties=domain_properties.
                            select {|prop| prop[1] == subdomain }.
                            collect{|prop| prop=prop.dup;prop[2]=upsc_context2mib_context(prop[2]);prop }.
                            collect{|prop| @enums["nutThreephaseContext"].include?(prop[2])? prop : (prop=prop.dup;prop.insert(2,"none");prop) }
                        next if subdomain_properties.empty?

                        @enums["nutThreephaseContext"].each do
                            |(context, context_id)|
                            any_context_property=subdomain_properties.
                                detect {|prop| prop[2] == context }
                            next if not any_context_property
                            #$stderr.puts "#{any_context_property.inspect} = #{[dev_id, domain_id, subdomain_id, context_id].inspect}"
                            indexes_for_device << [dev_id, domain_id.to_i, subdomain_id.to_i, context_id.to_i]
                        end
                    end
                end
            end
            #$stderr.puts "#{indexes_for_device}"
            indexes_for_device
        end.inject([],:+)
    end

    def nutThreephaseDomain(deviceIndex, threephaseDomainIndex, threephaseSubDomainIndex, threephaseContext)
        threephaseDomainIndex
    end
    def nutThreephaseSubdomain(deviceIndex, threephaseDomainIndex, threephaseSubdomainIndex, threephaseContext)
        threephaseSubdomainIndex
    end
    def nutThreephaseContext(deviceIndex, threephaseDomainIndex, threephaseSubDomainIndex, threephaseContext)
        threephaseContext
    end

    class Upsc
        def upsc(args)
            res=`upsc #{args}`
            raise "Command 'upsc #{args}' failed with error code #{$?}" if not $?==0
            return res
        end

        def split(txt)
            # The order is kept only on ruby>1.9. Not the correct check but it will work
            # raise "Order kept only in ruby>1.9" if RUBY_VERSION<"1.9"
            if RUBY_VERSION<"1.9"
                OrderedHash[*txt.split("\n").collect {|line| line.split(": ",2) }.flatten]
            else
                Hash[*txt.split("\n").collect {|line| line.split(": ",2) }.flatten]
            end
        end

        def [](device_name,name)
            property(device_name,name)
        end

        def property(device_name,name)
            if not device_name
                txt=upsc(name)
            else
                txt=upsc("#{device_name} #{name}")
            end
            txt.chomp! if txt
            return txt
        end
    
        def devices
            split(upsc("-L"))
        end

        def device(name)
            split(upsc(name))
        end

        def properties(name)
            device(name).keys
        end
    end

    # Cache values for a given cache_lifetime seconds
    class CachedUpsc < Upsc
        include CachedMethod
        extend CachedMethod

        def initialize
            @cache=Hash.new
        end

        cache_method :devices, 60
        cache_method :device, 60

        # Use the device cache instead
        def property(device_name,name)
            return super(device_name,name) if device_name == SERVER
            found=device(device_name).detect {|(prop,_)| prop==name }
            return found.last if found
        end
    end
end

class FakeNut < Nut
    class FakeUpsc < Upsc
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
                return "input.phases: 3\ninput.L2.current: 48.2\ninput.N.current: 3.4\ninput.L3-L1.voltage: 405.4\ninput.frequency: 50.1\noutput.phases: 1\noutput.current: 244.2\noutput.voltage: 120\noutput.frequency.nominal: 60.0"
            when "ups3"
                return "battery.charge: 100\nbattery.charge.low: 20\nbattery.runtime: 2525\nbattery.type: PbAc\ndevice.mfr: EATON\ndevice.model: Ellipse MAX 1100\ndevice.serial: ADKK22008\ndevice.type: ups\ndriver.name: usbhid-ups\ndriver.parameter.pollfreq: 30\ndriver.parameter.pollinterval: 2\ndriver.parameter.port: auto\ndriver.version: 2.4.1-1988:1990M\ndriver.version.data: MGE HID 1.12\ndriver.version.internal: 0.34\ninput.sensitivity: normal\ninput.transfer.boost.low: 185\ninput.transfer.high: 285\ninput.transfer.low: 165\ninput.transfer.trim.high: 265\ninput.voltage.extended: no\noutlet.1.desc: PowerShare Outlet 1\noutlet.1.id: 2\noutlet.1.status: on\noutlet.1.switchable: no\noutlet.desc: Main Outlet\noutlet.id: 1\noutlet.switchable: no\noutput.frequency.nominal: 50\noutput.voltage: 230.0\noutput.voltage.nominal: 230\nups.beeper.status: enabled\nups.delay.shutdown: 20\nups.delay.start: 30\nups.firmware: 5102AH\nups.load: 0\nups.mfr: EATON\nups.model: Ellipse MAX 1100\nups.power.nominal: 1100\nups.productid: ffff\nups.serial: ADKK22008\nups.status: OL CHRG\nups.timer.shutdown: -1\nups.timer.start: -1\nups.vendorid: 0463"
            when /^#{Nut::SERVER} /
                case args
                    when / server\.info$/
                    return "serverinfo example"
                when / server\.version$/
                    return "test server version"
                end
            when /[[:alnum:]]+ [[:alnum:]\.]+/
                (name,target_prop)=args.split(" ")
                found=split(upsc(name)).detect{|(prop,_)| prop==target_prop }
                return found.last if found
            end
            nil
        end
    end

    def initialize(mibxml)
        super(mibxml)
        @upsc=FakeUpsc.new
    end
end

#FakeNut.start_embebedmib(ARGV)
Nut.start_embebedmib(ARGV)

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
    <revision date="2012-06-11 00:00">
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
    <typedef name="NutDeviceIndexType" basetype="Integer32" status="current">
      <range min="1" max="2147483647"/>
      <format>d</format>
      <description>
          A unique value, greater than zero, for each device. It is
          recommended that values are assigned contiguously starting
          from 1.
      </description>
    </typedef>
    <typedef name="NutOutletIndexType" basetype="Integer32" status="current">
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
    <table name="nutDeviceTable" oid="1.3.6.1.4.1.26376.99.1.1" status="current">
      <description>
          A list of device.
      </description>
      <row name="nutDeviceEntry" oid="1.3.6.1.4.1.26376.99.1.1.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular device.
        </description>
        <column name="nutDeviceIndex" oid="1.3.6.1.4.1.26376.99.1.1.1.1" status="current">
          <syntax>
            <type module="NUT-MIB" name="NutDeviceIndexType"/>
          </syntax>
          <access>noaccess</access>
          <description>
              A unique value, greater than zero, for each device
          </description>
        </column>
        <column name="nutDeviceName" oid="1.3.6.1.4.1.26376.99.1.1.1.2" status="current">
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
        <column name="nutDeviceDesc" oid="1.3.6.1.4.1.26376.99.1.1.1.3" status="current">
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
        <column name="nutDeviceModel" oid="1.3.6.1.4.1.26376.99.1.1.1.4" status="current">
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
        <column name="nutDeviceMfr" oid="1.3.6.1.4.1.26376.99.1.1.1.5" status="current">
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
        <column name="nutDeviceSerial" oid="1.3.6.1.4.1.26376.99.1.1.1.6" status="current">
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
        <column name="nutDeviceType" oid="1.3.6.1.4.1.26376.99.1.1.1.7" status="current">
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
    <table name="nutUpsTable" oid="1.3.6.1.4.1.26376.99.1.2" status="current">
      <description>
          A list of ups.
      </description>
      <row name="nutUpsEntry" oid="1.3.6.1.4.1.26376.99.1.2.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular ups.
        </description>
        <column name="nutUpsStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.1" status="current">
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
        <column name="nutUpsAlarm" oid="1.3.6.1.4.1.26376.99.1.2.1.2" status="current">
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
        <column name="nutUpsTime" oid="1.3.6.1.4.1.26376.99.1.2.1.3" status="current">
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
        <column name="nutUpsDate" oid="1.3.6.1.4.1.26376.99.1.2.1.4" status="current">
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
        <column name="nutUpsModel" oid="1.3.6.1.4.1.26376.99.1.2.1.5" status="current">
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
        <column name="nutUpsMfr" oid="1.3.6.1.4.1.26376.99.1.2.1.6" status="current">
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
        <column name="nutUpsMfrDate" oid="1.3.6.1.4.1.26376.99.1.2.1.7" status="current">
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
        <column name="nutUpsSerial" oid="1.3.6.1.4.1.26376.99.1.2.1.8" status="current">
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
        <column name="nutUpsVendorid" oid="1.3.6.1.4.1.26376.99.1.2.1.9" status="current">
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
        <column name="nutUpsProductid" oid="1.3.6.1.4.1.26376.99.1.2.1.10" status="current">
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
        <column name="nutUpsFirmware" oid="1.3.6.1.4.1.26376.99.1.2.1.11" status="current">
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
        <column name="nutUpsFirmwareAux" oid="1.3.6.1.4.1.26376.99.1.2.1.12" status="current">
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
        <column name="nutUpsTemperature" oid="1.3.6.1.4.1.26376.99.1.2.1.13" status="current">
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
        <column name="nutUpsLoad" oid="1.3.6.1.4.1.26376.99.1.2.1.14" status="current">
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
        <column name="nutUpsLoadHigh" oid="1.3.6.1.4.1.26376.99.1.2.1.15" status="current">
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
        <column name="nutUpsId" oid="1.3.6.1.4.1.26376.99.1.2.1.16" status="current">
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
        <column name="nutUpsDelayStart" oid="1.3.6.1.4.1.26376.99.1.2.1.17" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before restarting the load (seconds). I.e. 0.
          </description>
        </column>
        <column name="nutUpsDelayReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.18" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before rebooting the UPS (seconds). I.e. 60.
          </description>
        </column>
        <column name="nutUpsDelayShutdown" oid="1.3.6.1.4.1.26376.99.1.2.1.19" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait after shutdown with delay command (seconds). I.e. 20.
          </description>
        </column>
        <column name="nutUpsTimerStart" oid="1.3.6.1.4.1.26376.99.1.2.1.20" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be started (seconds). I.e. 30.
          </description>
        </column>
        <column name="nutUpsTimerReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.21" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be rebooted (seconds). I.e. 10.
          </description>
        </column>
        <column name="nutUpsTimerShutdown" oid="1.3.6.1.4.1.26376.99.1.2.1.22" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Time before the load will be shutdown (seconds). I.e. 20.
          </description>
        </column>
        <column name="nutUpsTestInterval" oid="1.3.6.1.4.1.26376.99.1.2.1.23" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval between self tests (seconds). I.e. 1209600 (two weeks).
          </description>
        </column>
        <column name="nutUpsTestResult" oid="1.3.6.1.4.1.26376.99.1.2.1.24" status="current">
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
        <column name="nutUpsDisplayLanguage" oid="1.3.6.1.4.1.26376.99.1.2.1.25" status="current">
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
        <column name="nutUpsContacts" oid="1.3.6.1.4.1.26376.99.1.2.1.26" status="current">
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
        <column name="nutUpsEfficiency" oid="1.3.6.1.4.1.26376.99.1.2.1.27" status="current">
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
        <column name="nutUpsPower" oid="1.3.6.1.4.1.26376.99.1.2.1.28" status="current">
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
        <column name="nutUpsPowerNominal" oid="1.3.6.1.4.1.26376.99.1.2.1.29" status="current">
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
        <column name="nutUpsRealpower" oid="1.3.6.1.4.1.26376.99.1.2.1.30" status="current">
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
        <column name="nutUpsRealpowerNominal" oid="1.3.6.1.4.1.26376.99.1.2.1.31" status="current">
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
        <column name="nutUpsBeeperStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.32" status="current">
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
        <column name="nutUpsType" oid="1.3.6.1.4.1.26376.99.1.2.1.33" status="current">
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
        <column name="nutUpsWatchdogStatus" oid="1.3.6.1.4.1.26376.99.1.2.1.34" status="current">
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
        <column name="nutUpsStartAuto" oid="1.3.6.1.4.1.26376.99.1.2.1.35" status="current">
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
        <column name="nutUpsStartBattery" oid="1.3.6.1.4.1.26376.99.1.2.1.36" status="current">
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
        <column name="nutUpsStartReboot" oid="1.3.6.1.4.1.26376.99.1.2.1.37" status="current">
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
    <table name="nutInputTable" oid="1.3.6.1.4.1.26376.99.1.3" status="current">
      <description>
          A list of input.
      </description>
      <row name="nutInputEntry" oid="1.3.6.1.4.1.26376.99.1.3.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular input.
        </description>
        <column name="nutInputVoltage" oid="1.3.6.1.4.1.26376.99.1.3.1.1" status="current">
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
        <column name="nutInputVoltageMaximum" oid="1.3.6.1.4.1.26376.99.1.3.1.2" status="current">
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
        <column name="nutInputVoltageMinimum" oid="1.3.6.1.4.1.26376.99.1.3.1.3" status="current">
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
        <column name="nutInputVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.4" status="current">
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
        <column name="nutInputVoltageExtended" oid="1.3.6.1.4.1.26376.99.1.3.1.5" status="current">
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
        <column name="nutInputTransferReason" oid="1.3.6.1.4.1.26376.99.1.3.1.6" status="current">
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
        <column name="nutInputTransferLow" oid="1.3.6.1.4.1.26376.99.1.3.1.7" status="current">
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
        <column name="nutInputTransferHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.8" status="current">
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
        <column name="nutInputTransferLowMin" oid="1.3.6.1.4.1.26376.99.1.3.1.9" status="current">
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
        <column name="nutInputTransferLowMax" oid="1.3.6.1.4.1.26376.99.1.3.1.10" status="current">
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
        <column name="nutInputTransferHighMin" oid="1.3.6.1.4.1.26376.99.1.3.1.11" status="current">
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
        <column name="nutInputTransferHighMax" oid="1.3.6.1.4.1.26376.99.1.3.1.12" status="current">
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
        <column name="nutInputSensitivity" oid="1.3.6.1.4.1.26376.99.1.3.1.13" status="current">
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
        <column name="nutInputQuality" oid="1.3.6.1.4.1.26376.99.1.3.1.14" status="current">
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
        <column name="nutInputCurrent" oid="1.3.6.1.4.1.26376.99.1.3.1.15" status="current">
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
        <column name="nutInputCurrentNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.16" status="current">
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
        <column name="nutInputFrequency" oid="1.3.6.1.4.1.26376.99.1.3.1.17" status="current">
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
        <column name="nutInputFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.3.1.18" status="current">
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
        <column name="nutInputFrequencyLow" oid="1.3.6.1.4.1.26376.99.1.3.1.19" status="current">
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
        <column name="nutInputFrequencyHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.20" status="current">
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
        <column name="nutInputFrequencyExtended" oid="1.3.6.1.4.1.26376.99.1.3.1.21" status="current">
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
        <column name="nutInputTransferBoostLow" oid="1.3.6.1.4.1.26376.99.1.3.1.22" status="current">
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
        <column name="nutInputTransferBoostHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.23" status="current">
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
        <column name="nutInputTransferTrimLow" oid="1.3.6.1.4.1.26376.99.1.3.1.24" status="current">
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
        <column name="nutInputTransferTrimHigh" oid="1.3.6.1.4.1.26376.99.1.3.1.25" status="current">
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
        <column name="nutInputPhases" oid="1.3.6.1.4.1.26376.99.1.3.1.26" status="current">
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
    <table name="nutOutputTable" oid="1.3.6.1.4.1.26376.99.1.4" status="current">
      <description>
          A list of output.
      </description>
      <row name="nutOutputEntry" oid="1.3.6.1.4.1.26376.99.1.4.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular output.
        </description>
        <column name="nutOutputVoltage" oid="1.3.6.1.4.1.26376.99.1.4.1.1" status="current">
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
        <column name="nutOutputVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.2" status="current">
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
        <column name="nutOutputFrequency" oid="1.3.6.1.4.1.26376.99.1.4.1.3" status="current">
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
        <column name="nutOutputFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.4" status="current">
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
        <column name="nutOutputCurrent" oid="1.3.6.1.4.1.26376.99.1.4.1.5" status="current">
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
        <column name="nutOutputCurrentNominal" oid="1.3.6.1.4.1.26376.99.1.4.1.6" status="current">
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
        <column name="nutOutputPhases" oid="1.3.6.1.4.1.26376.99.1.4.1.7" status="current">
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
    <table name="nutBatteryTable" oid="1.3.6.1.4.1.26376.99.1.5" status="current">
      <description>
          A list of battery.
      </description>
      <row name="nutBatteryEntry" oid="1.3.6.1.4.1.26376.99.1.5.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular battery.
        </description>
        <column name="nutBatteryCharge" oid="1.3.6.1.4.1.26376.99.1.5.1.1" status="current">
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
        <column name="nutBatteryChargeLow" oid="1.3.6.1.4.1.26376.99.1.5.1.2" status="current">
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
        <column name="nutBatteryChargeRestart" oid="1.3.6.1.4.1.26376.99.1.5.1.3" status="current">
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
        <column name="nutBatteryChargeWarning" oid="1.3.6.1.4.1.26376.99.1.5.1.4" status="current">
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
        <column name="nutBatteryVoltage" oid="1.3.6.1.4.1.26376.99.1.5.1.5" status="current">
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
        <column name="nutBatteryCapacity" oid="1.3.6.1.4.1.26376.99.1.5.1.6" status="current">
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
        <column name="nutBatteryCurrent" oid="1.3.6.1.4.1.26376.99.1.5.1.7" status="current">
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
        <column name="nutBatteryTemperature" oid="1.3.6.1.4.1.26376.99.1.5.1.8" status="current">
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
        <column name="nutBatteryVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.5.1.9" status="current">
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
        <column name="nutBatteryRuntime" oid="1.3.6.1.4.1.26376.99.1.5.1.10" status="current">
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
        <column name="nutBatteryRuntimeLow" oid="1.3.6.1.4.1.26376.99.1.5.1.11" status="current">
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
        <column name="nutBatteryAlarmThreshold" oid="1.3.6.1.4.1.26376.99.1.5.1.12" status="current">
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
        <column name="nutBatteryDate" oid="1.3.6.1.4.1.26376.99.1.5.1.13" status="current">
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
        <column name="nutBatteryMfrDate" oid="1.3.6.1.4.1.26376.99.1.5.1.14" status="current">
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
        <column name="nutBatteryPacks" oid="1.3.6.1.4.1.26376.99.1.5.1.15" status="current">
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
        <column name="nutBatteryPacksBad" oid="1.3.6.1.4.1.26376.99.1.5.1.16" status="current">
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
        <column name="nutBatteryType" oid="1.3.6.1.4.1.26376.99.1.5.1.17" status="current">
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
        <column name="nutBatteryProtection" oid="1.3.6.1.4.1.26376.99.1.5.1.18" status="current">
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
        <column name="nutBatteryEnergysave" oid="1.3.6.1.4.1.26376.99.1.5.1.19" status="current">
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
    <table name="nutAmbientTable" oid="1.3.6.1.4.1.26376.99.1.6" status="current">
      <description>
          A list of device ambient information.
      </description>
      <row name="nutAmbientEntry" oid="1.3.6.1.4.1.26376.99.1.6.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular ambient.
        </description>
        <column name="nutAmbientTemperature" oid="1.3.6.1.4.1.26376.99.1.6.1.1" status="current">
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
        <column name="nutAmbientTemperatureAlarm" oid="1.3.6.1.4.1.26376.99.1.6.1.2" status="current">
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
        <column name="nutAmbientTemperatureHigh" oid="1.3.6.1.4.1.26376.99.1.6.1.3" status="current">
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
        <column name="nutAmbientTemperatureLow" oid="1.3.6.1.4.1.26376.99.1.6.1.4" status="current">
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
        <column name="nutAmbientTemperatureMaximum" oid="1.3.6.1.4.1.26376.99.1.6.1.5" status="current">
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
        <column name="nutAmbientTemperatureMinimum" oid="1.3.6.1.4.1.26376.99.1.6.1.6" status="current">
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
        <column name="nutAmbientHumidity" oid="1.3.6.1.4.1.26376.99.1.6.1.7" status="current">
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
        <column name="nutAmbientHumidityAlarm" oid="1.3.6.1.4.1.26376.99.1.6.1.8" status="current">
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
        <column name="nutAmbientHumidityHigh" oid="1.3.6.1.4.1.26376.99.1.6.1.9" status="current">
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
        <column name="nutAmbientHumidityLow" oid="1.3.6.1.4.1.26376.99.1.6.1.10" status="current">
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
        <column name="nutAmbientHumidityMaximum" oid="1.3.6.1.4.1.26376.99.1.6.1.11" status="current">
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
        <column name="nutAmbientHumidityMinimum" oid="1.3.6.1.4.1.26376.99.1.6.1.12" status="current">
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
    <table name="nutOutletTable" oid="1.3.6.1.4.1.26376.99.1.7" status="current">
      <description>
          A list of nutOutlet.
      </description>
      <row name="nutOutletEntry" oid="1.3.6.1.4.1.26376.99.1.7.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
          <index module="NUT-MIB" name="nutOutletIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular outlet.
        </description>
        <column name="nutOutletIndex" oid="1.3.6.1.4.1.26376.99.1.7.1.1" status="current">
          <syntax>
            <type module="NUT-MIB" name="NutOutletIndexType"/>
          </syntax>
          <access>noaccess</access>
          <description>
              A unique value, greater than or equal to zero, for each outlet. It stands for the outlet index.
              A special case is 0 which represents the whole set of outlets of the device.
          </description>
        </column>
        <column name="nutOutletId" oid="1.3.6.1.4.1.26376.99.1.7.1.2" status="current">
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
        <column name="nutOutletDesc" oid="1.3.6.1.4.1.26376.99.1.7.1.3" status="current">
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
        <column name="nutOutletSwitch" oid="1.3.6.1.4.1.26376.99.1.7.1.4" status="current">
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
        <column name="nutOutletStatus" oid="1.3.6.1.4.1.26376.99.1.7.1.5" status="current">
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
        <column name="nutOutletSwitchable" oid="1.3.6.1.4.1.26376.99.1.7.1.6" status="current">
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
        <column name="nutOutletAutoswitchChargeLow" oid="1.3.6.1.4.1.26376.99.1.7.1.7" status="current">
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
        <column name="nutOutletDelayShutdown" oid="1.3.6.1.4.1.26376.99.1.7.1.8" status="current">
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
        <column name="nutOutletDelayStart" oid="1.3.6.1.4.1.26376.99.1.7.1.9" status="current">
          <syntax>
            <typedef basetype="Integer32">
              <range min="-1" max="2147483647"/>
            </typedef>
          </syntax>
          <access>readonly</access>
          <description>
              Interval to wait before restarting this outlet (seconds). I.e. 120.
          </description>
        </column>
        <column name="nutOutletCurrent" oid="1.3.6.1.4.1.26376.99.1.7.1.10" status="current">
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
        <column name="nutOutletCurrentMaximum" oid="1.3.6.1.4.1.26376.99.1.7.1.11" status="current">
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
        <column name="nutOutletRealpower" oid="1.3.6.1.4.1.26376.99.1.7.1.12" status="current">
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
        <column name="nutOutletVoltage" oid="1.3.6.1.4.1.26376.99.1.7.1.13" status="current">
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
        <column name="nutOutletPowerfactor" oid="1.3.6.1.4.1.26376.99.1.7.1.14" status="current">
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
        <column name="nutOutletCrestfactor" oid="1.3.6.1.4.1.26376.99.1.7.1.15" status="current">
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
        <column name="nutOutletPower" oid="1.3.6.1.4.1.26376.99.1.7.1.16" status="current">
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
    <table name="nutDriverTable" oid="1.3.6.1.4.1.26376.99.1.8" status="current">
      <description>
          A list of drivers.
      </description>
      <row name="nutDriverEntry" oid="1.3.6.1.4.1.26376.99.1.8.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
        </linkage>
        <description>
            An entry containing information about a particular driver.
        </description>
        <column name="nutDriverName" oid="1.3.6.1.4.1.26376.99.1.8.1.1" status="current">
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
        <column name="nutDriverVersion" oid="1.3.6.1.4.1.26376.99.1.8.1.2" status="current">
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
        <column name="nutDriverVersionInternal" oid="1.3.6.1.4.1.26376.99.1.8.1.3" status="current">
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
    <node name="nutServerObjects" oid="1.3.6.1.4.1.26376.99.1.9">
    </node>
    <scalar name="nutServerInfo" oid="1.3.6.1.4.1.26376.99.1.9.1" status="current">
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
    <scalar name="nutServerVersion" oid="1.3.6.1.4.1.26376.99.1.9.2" status="current">
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
    <table name="nutThreephaseTable" oid="1.3.6.1.4.1.26376.99.1.10" status="current">
      <description>
          A list of three-phase device information.
      </description>
      <row name="nutThreephaseEntry" oid="1.3.6.1.4.1.26376.99.1.10.1" status="current">
        <linkage>
          <index module="NUT-MIB" name="nutDeviceIndex"/>
          <index module="NUT-MIB" name="nutThreephaseDomain"/>
          <index module="NUT-MIB" name="nutThreephaseSubdomain"/>
          <index module="NUT-MIB" name="nutThreephaseContext"/>
        </linkage>
        <description>
            An entry containing information about a particular driver.
        </description>
        <column name="nutThreephaseDomain" oid="1.3.6.1.4.1.26376.99.1.10.1.1" status="current">
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
        <column name="nutThreephaseSubdomain" oid="1.3.6.1.4.1.26376.99.1.10.1.2" status="current">
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
        <column name="nutThreephaseContext" oid="1.3.6.1.4.1.26376.99.1.10.1.3" status="current">
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
        <column name="nutThreephaseCurrent" oid="1.3.6.1.4.1.26376.99.1.10.1.4" status="current">
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
        <column name="nutThreephaseCurrentMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.5" status="current">
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
        <column name="nutThreephaseCurrentMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.6" status="current">
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
        <column name="nutThreephaseCurrentPeak" oid="1.3.6.1.4.1.26376.99.1.10.1.7" status="current">
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
        <column name="nutThreephaseVoltage" oid="1.3.6.1.4.1.26376.99.1.10.1.8" status="current">
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
        <column name="nutThreephaseVoltageNominal" oid="1.3.6.1.4.1.26376.99.1.10.1.9" status="current">
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
        <column name="nutThreephaseVoltageMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.10" status="current">
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
        <column name="nutThreephaseVoltageMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.11" status="current">
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
        <column name="nutThreephasePower" oid="1.3.6.1.4.1.26376.99.1.10.1.12" status="current">
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
        <column name="nutThreephasePowerMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.13" status="current">
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
        <column name="nutThreephasePowerMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.14" status="current">
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
        <column name="nutThreephasePowerPercent" oid="1.3.6.1.4.1.26376.99.1.10.1.15" status="current">
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
        <column name="nutThreephasePowerPercentMaximum" oid="1.3.6.1.4.1.26376.99.1.10.1.16" status="current">
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
        <column name="nutThreephasePowerPercentMinimum" oid="1.3.6.1.4.1.26376.99.1.10.1.17" status="current">
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
        <column name="nutThreephaseRealpower" oid="1.3.6.1.4.1.26376.99.1.10.1.18" status="current">
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
        <column name="nutThreephasePowerfactor" oid="1.3.6.1.4.1.26376.99.1.10.1.19" status="current">
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
        <column name="nutThreephaseCrestfactor" oid="1.3.6.1.4.1.26376.99.1.10.1.20" status="current">
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
        <column name="nutThreephaseFrequency" oid="1.3.6.1.4.1.26376.99.1.10.1.21" status="current">
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
        <column name="nutThreephaseFrequencyNominal" oid="1.3.6.1.4.1.26376.99.1.10.1.22" status="current">
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
        <member module="NUT-MIB" name="nutDeviceName"/>
        <member module="NUT-MIB" name="nutDeviceDesc"/>
        <member module="NUT-MIB" name="nutDeviceModel"/>
        <member module="NUT-MIB" name="nutDeviceMfr"/>
        <member module="NUT-MIB" name="nutDeviceSerial"/>
        <member module="NUT-MIB" name="nutDeviceType"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a device
      </description>
    </group>
    <group name="nutUpsGroup" oid="1.3.6.1.4.1.26376.99.2.1.2" status="current">
      <members>
        <member module="NUT-MIB" name="nutUpsStatus"/>
        <member module="NUT-MIB" name="nutUpsAlarm"/>
        <member module="NUT-MIB" name="nutUpsTime"/>
        <member module="NUT-MIB" name="nutUpsDate"/>
        <member module="NUT-MIB" name="nutUpsModel"/>
        <member module="NUT-MIB" name="nutUpsMfr"/>
        <member module="NUT-MIB" name="nutUpsMfrDate"/>
        <member module="NUT-MIB" name="nutUpsSerial"/>
        <member module="NUT-MIB" name="nutUpsVendorid"/>
        <member module="NUT-MIB" name="nutUpsProductid"/>
        <member module="NUT-MIB" name="nutUpsFirmware"/>
        <member module="NUT-MIB" name="nutUpsFirmwareAux"/>
        <member module="NUT-MIB" name="nutUpsTemperature"/>
        <member module="NUT-MIB" name="nutUpsLoad"/>
        <member module="NUT-MIB" name="nutUpsLoadHigh"/>
        <member module="NUT-MIB" name="nutUpsId"/>
        <member module="NUT-MIB" name="nutUpsDelayStart"/>
        <member module="NUT-MIB" name="nutUpsDelayReboot"/>
        <member module="NUT-MIB" name="nutUpsDelayShutdown"/>
        <member module="NUT-MIB" name="nutUpsTimerStart"/>
        <member module="NUT-MIB" name="nutUpsTimerReboot"/>
        <member module="NUT-MIB" name="nutUpsTimerShutdown"/>
        <member module="NUT-MIB" name="nutUpsTestInterval"/>
        <member module="NUT-MIB" name="nutUpsTestResult"/>
        <member module="NUT-MIB" name="nutUpsDisplayLanguage"/>
        <member module="NUT-MIB" name="nutUpsContacts"/>
        <member module="NUT-MIB" name="nutUpsEfficiency"/>
        <member module="NUT-MIB" name="nutUpsPower"/>
        <member module="NUT-MIB" name="nutUpsPowerNominal"/>
        <member module="NUT-MIB" name="nutUpsRealpower"/>
        <member module="NUT-MIB" name="nutUpsRealpowerNominal"/>
        <member module="NUT-MIB" name="nutUpsBeeperStatus"/>
        <member module="NUT-MIB" name="nutUpsType"/>
        <member module="NUT-MIB" name="nutUpsWatchdogStatus"/>
        <member module="NUT-MIB" name="nutUpsStartAuto"/>
        <member module="NUT-MIB" name="nutUpsStartBattery"/>
        <member module="NUT-MIB" name="nutUpsStartReboot"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a device
      </description>
    </group>
    <group name="nutInputGroup" oid="1.3.6.1.4.1.26376.99.2.1.3" status="current">
      <members>
        <member module="NUT-MIB" name="nutInputVoltage"/>
        <member module="NUT-MIB" name="nutInputVoltageMaximum"/>
        <member module="NUT-MIB" name="nutInputVoltageMinimum"/>
        <member module="NUT-MIB" name="nutInputVoltageNominal"/>
        <member module="NUT-MIB" name="nutInputVoltageExtended"/>
        <member module="NUT-MIB" name="nutInputTransferReason"/>
        <member module="NUT-MIB" name="nutInputTransferLow"/>
        <member module="NUT-MIB" name="nutInputTransferHigh"/>
        <member module="NUT-MIB" name="nutInputTransferLowMin"/>
        <member module="NUT-MIB" name="nutInputTransferLowMax"/>
        <member module="NUT-MIB" name="nutInputTransferHighMin"/>
        <member module="NUT-MIB" name="nutInputTransferHighMax"/>
        <member module="NUT-MIB" name="nutInputSensitivity"/>
        <member module="NUT-MIB" name="nutInputQuality"/>
        <member module="NUT-MIB" name="nutInputCurrent"/>
        <member module="NUT-MIB" name="nutInputCurrentNominal"/>
        <member module="NUT-MIB" name="nutInputFrequency"/>
        <member module="NUT-MIB" name="nutInputFrequencyNominal"/>
        <member module="NUT-MIB" name="nutInputFrequencyLow"/>
        <member module="NUT-MIB" name="nutInputFrequencyHigh"/>
        <member module="NUT-MIB" name="nutInputFrequencyExtended"/>
        <member module="NUT-MIB" name="nutInputTransferBoostLow"/>
        <member module="NUT-MIB" name="nutInputTransferBoostHigh"/>
        <member module="NUT-MIB" name="nutInputTransferTrimLow"/>
        <member module="NUT-MIB" name="nutInputTransferTrimHigh"/>
        <member module="NUT-MIB" name="nutInputPhases"/>
      </members>
      <description>
          A collection of objects providing information specific to
          an input of a device
      </description>
    </group>
    <group name="nutOutputGroup" oid="1.3.6.1.4.1.26376.99.2.1.4" status="current">
      <members>
        <member module="NUT-MIB" name="nutOutputVoltage"/>
        <member module="NUT-MIB" name="nutOutputVoltageNominal"/>
        <member module="NUT-MIB" name="nutOutputFrequency"/>
        <member module="NUT-MIB" name="nutOutputFrequencyNominal"/>
        <member module="NUT-MIB" name="nutOutputCurrent"/>
        <member module="NUT-MIB" name="nutOutputCurrentNominal"/>
        <member module="NUT-MIB" name="nutOutputPhases"/>
      </members>
      <description>
          A collection of objects providing information specific to
          an output of a device
      </description>
    </group>
    <group name="nutBatteryGroup" oid="1.3.6.1.4.1.26376.99.2.1.5" status="current">
      <members>
        <member module="NUT-MIB" name="nutBatteryCharge"/>
        <member module="NUT-MIB" name="nutBatteryChargeLow"/>
        <member module="NUT-MIB" name="nutBatteryChargeRestart"/>
        <member module="NUT-MIB" name="nutBatteryChargeWarning"/>
        <member module="NUT-MIB" name="nutBatteryVoltage"/>
        <member module="NUT-MIB" name="nutBatteryCapacity"/>
        <member module="NUT-MIB" name="nutBatteryCurrent"/>
        <member module="NUT-MIB" name="nutBatteryTemperature"/>
        <member module="NUT-MIB" name="nutBatteryVoltageNominal"/>
        <member module="NUT-MIB" name="nutBatteryRuntime"/>
        <member module="NUT-MIB" name="nutBatteryRuntimeLow"/>
        <member module="NUT-MIB" name="nutBatteryAlarmThreshold"/>
        <member module="NUT-MIB" name="nutBatteryDate"/>
        <member module="NUT-MIB" name="nutBatteryMfrDate"/>
        <member module="NUT-MIB" name="nutBatteryPacks"/>
        <member module="NUT-MIB" name="nutBatteryPacksBad"/>
        <member module="NUT-MIB" name="nutBatteryType"/>
        <member module="NUT-MIB" name="nutBatteryProtection"/>
        <member module="NUT-MIB" name="nutBatteryEnergysave"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a baterry of a device
      </description>
    </group>
    <group name="nutAmbientGroup" oid="1.3.6.1.4.1.26376.99.2.1.6" status="current">
      <members>
        <member module="NUT-MIB" name="nutAmbientTemperature"/>
        <member module="NUT-MIB" name="nutAmbientTemperatureAlarm"/>
        <member module="NUT-MIB" name="nutAmbientTemperatureHigh"/>
        <member module="NUT-MIB" name="nutAmbientTemperatureLow"/>
        <member module="NUT-MIB" name="nutAmbientTemperatureMaximum"/>
        <member module="NUT-MIB" name="nutAmbientTemperatureMinimum"/>
        <member module="NUT-MIB" name="nutAmbientHumidity"/>
        <member module="NUT-MIB" name="nutAmbientHumidityAlarm"/>
        <member module="NUT-MIB" name="nutAmbientHumidityHigh"/>
        <member module="NUT-MIB" name="nutAmbientHumidityLow"/>
        <member module="NUT-MIB" name="nutAmbientHumidityMaximum"/>
        <member module="NUT-MIB" name="nutAmbientHumidityMinimum"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the ambient of a device
      </description>
    </group>
    <group name="nutOutletGroup" oid="1.3.6.1.4.1.26376.99.2.1.7" status="current">
      <members>
        <member module="NUT-MIB" name="nutOutletId"/>
        <member module="NUT-MIB" name="nutOutletDesc"/>
        <member module="NUT-MIB" name="nutOutletSwitch"/>
        <member module="NUT-MIB" name="nutOutletStatus"/>
        <member module="NUT-MIB" name="nutOutletSwitchable"/>
        <member module="NUT-MIB" name="nutOutletAutoswitchChargeLow"/>
        <member module="NUT-MIB" name="nutOutletDelayShutdown"/>
        <member module="NUT-MIB" name="nutOutletDelayStart"/>
        <member module="NUT-MIB" name="nutOutletCurrent"/>
        <member module="NUT-MIB" name="nutOutletCurrentMaximum"/>
        <member module="NUT-MIB" name="nutOutletRealpower"/>
        <member module="NUT-MIB" name="nutOutletVoltage"/>
        <member module="NUT-MIB" name="nutOutletPowerfactor"/>
        <member module="NUT-MIB" name="nutOutletCrestfactor"/>
        <member module="NUT-MIB" name="nutOutletPower"/>
      </members>
      <description>
          A collection of objects providing information specific to
          a outlet of a device
      </description>
    </group>
    <group name="nutDriverGroup" oid="1.3.6.1.4.1.26376.99.2.1.8" status="current">
      <members>
        <member module="NUT-MIB" name="nutDriverName"/>
        <member module="NUT-MIB" name="nutDriverVersion"/>
        <member module="NUT-MIB" name="nutDriverVersionInternal"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the driver of a device
      </description>
    </group>
    <group name="nutServerGroup" oid="1.3.6.1.4.1.26376.99.2.1.9" status="current">
      <members>
        <member module="NUT-MIB" name="nutServerInfo"/>
        <member module="NUT-MIB" name="nutServerVersion"/>
      </members>
      <description>
          A collection of objects providing information specific to
          the server
      </description>
    </group>
    <group name="nutThreephaseGroup" oid="1.3.6.1.4.1.26376.99.2.1.10" status="current">
      <members>
        <member module="NUT-MIB" name="nutThreephaseCurrent"/>
        <member module="NUT-MIB" name="nutThreephaseCurrentMaximum"/>
        <member module="NUT-MIB" name="nutThreephaseCurrentMinimum"/>
        <member module="NUT-MIB" name="nutThreephaseCurrentPeak"/>
        <member module="NUT-MIB" name="nutThreephaseVoltage"/>
        <member module="NUT-MIB" name="nutThreephaseVoltageNominal"/>
        <member module="NUT-MIB" name="nutThreephaseVoltageMaximum"/>
        <member module="NUT-MIB" name="nutThreephaseVoltageMinimum"/>
        <member module="NUT-MIB" name="nutThreephasePower"/>
        <member module="NUT-MIB" name="nutThreephasePowerMaximum"/>
        <member module="NUT-MIB" name="nutThreephasePowerMinimum"/>
        <member module="NUT-MIB" name="nutThreephasePowerPercent"/>
        <member module="NUT-MIB" name="nutThreephasePowerPercentMaximum"/>
        <member module="NUT-MIB" name="nutThreephasePowerPercentMinimum"/>
        <member module="NUT-MIB" name="nutThreephaseRealpower"/>
        <member module="NUT-MIB" name="nutThreephasePowerfactor"/>
        <member module="NUT-MIB" name="nutThreephaseCrestfactor"/>
        <member module="NUT-MIB" name="nutThreephaseFrequency"/>
        <member module="NUT-MIB" name="nutThreephaseFrequencyNominal"/>
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
        <option module="NUT-MIB" name="nutOutputGroup">
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
