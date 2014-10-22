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
