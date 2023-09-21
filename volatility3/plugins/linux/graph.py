import os
import time
from dataclasses import dataclass
from enum import Enum
from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.exceptions import LayerException, SymbolError
from volatility3.framework.interfaces.context import ModuleInterface
from volatility3.framework.interfaces.objects import ObjectInterface, Template
from volatility3.framework.objects import Pointer, StructType
from volatility3.framework.renderers import format_hints
from graphviz import Digraph

OUTPUT_FOLDER = "/home/clement/Documents/seminar_data/results3/"
TIME_FILE = "timing_results.txt"
BEGIN_STRUCT_NAME = "cpuhp_cpu_state"

GENERATE_POINTER = True

class Edge(Enum):
    """
    the type of the edge
    """
    STRUCT = "struct"
    POINTER = "pointer"

class NodeType(Enum):
    """
    the type of the node (struct or basic)
    """
    STRUCT = "struct"
    BASIC = "basic"
    POINTER = "pointer"

    def get_from_obj(obj : ObjectInterface) -> "NodeType":
        if _is_struct(obj):
            return NodeType.STRUCT
        elif _is_pointer(obj):
            return NodeType.POINTER
        else:
            return NodeType.BASIC

    def get_str_for_graph_from_addr(self, addr : int) -> str:
        return f"{self.value}({addr})"

@dataclass
class NodeAddr:
    """
    define the addr of a node of the graph
    """
    addr : int
    node_type : NodeType

    def __init__(self, obj : ObjectInterface):
        """
        construct a NodeAddr from an ObjectInterface
        """
        self.addr = obj.vol.offset
        self.node_type = NodeType.get_from_obj(obj)

    def __str__(self) -> str:
        return self.node_type.get_str_for_graph_from_addr(str(self.addr))


class Graph(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    _graph : Digraph
    _nodes_addr : list[str]

    _vmlinux : ModuleInterface

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                            architectures = ["Intel32", "Intel64"])]
    
    def run(self):
        return renderers.TreeGrid([("name", str), ("addr", format_hints.Hex), ("output_file", str), ("time (s)", float)], self._generator())
    

    def _generator(
        self
    ):
        # get the vmlinux module
        vmlinux_module_name = self.config["kernel"]
        self._vmlinux = self.context.modules[vmlinux_module_name]

        type_name = self._vmlinux.symbol_table_name + constants.BANG + BEGIN_STRUCT_NAME

        found_symbol = []

        for symbol in self._vmlinux.symbols:
            try:
                obj = self._vmlinux.object_from_symbol(symbol_name = symbol, absolute=True)
                if obj.vol.type_name == type_name:
                    found_symbol.append(symbol)
                elif _is_pointer(obj):
                    obj = obj.dereference()
                    if obj.vol.type_name == type_name:
                        found_symbol.append(symbol)
            except SymbolError:
                pass
            except LayerException:
                pass

        all_time = 0
        
        for symbol in found_symbol:
            start_time = time.time()
            try:
                
                # get the struct
                struct_obj = self._vmlinux.object_from_symbol(symbol_name = symbol, absolute=True)
                self._graph = Digraph(comment=f"The {symbol} struct")
                self._nodes_addr = []

                self._generate_graph(struct_obj)

                # render the graph
                output_file = os.path.join(OUTPUT_FOLDER, f"{symbol}.gv")
                self._graph.render(output_file, view=False)

                end_time = time.time()
                elapsed_time = end_time - start_time
                all_time += elapsed_time

                with open(os.path.join(OUTPUT_FOLDER, TIME_FILE), 'a') as f:
                    f.write(f"{elapsed_time}\n")

                yield (0, (symbol, format_hints.Hex(struct_obj.vol.offset), output_file, elapsed_time))
            except LayerException:
                end_time = time.time()
                elapsed_time = end_time - start_time
                yield (0, (symbol, format_hints.Hex(0), "LayerException !", elapsed_time))


        if len(found_symbol) > 0:
            with open(os.path.join(OUTPUT_FOLDER, TIME_FILE), 'a') as f:
                f.write(f"cumulatif time (s) : {all_time}\n")
                f.write(f"mean : {all_time/len(found_symbol)}\n")
        else:
            yield (0, ("no symbol found", format_hints.Hex(0), "error !", 0.0))

    def _generate_graph(self, obj : ObjectInterface):
        """
        generate the graph from the obj
        """
        # if the first obj is a pointer, and we don't want to generate pointer, we follow the pointer one time
        if not GENERATE_POINTER and _is_pointer(obj):
            obj = obj.dereference()

        # generate the graph
        self.__add_node_wrapper(NodeAddr(obj), f"{BEGIN_STRUCT_NAME}({obj.vol.type_name})")

        self._generate_graph_rec(obj, NodeAddr(obj))

    def _generate_graph_rec(self, obj : ObjectInterface, parent_addr : NodeAddr):
        if _is_struct(obj):
            self._generate_struct_graph_v2(obj, parent_addr)

        if GENERATE_POINTER and _is_pointer(obj):
            self._generate_pointer_graph(obj, parent_addr)


    def _generate_struct_graph_v2(self, obj : ObjectInterface, parent_addr : NodeAddr):

        if not _is_struct(obj):
            raise Exception("obj is not a struct")

        members_names = _get_struct_members(obj)
        if len(members_names) == 0:
            # stop condition
            return
        

        for member_name in members_names:
            member_infos = members_names[member_name]
            member_type_infos = member_infos[1] # member type infos
            member_type = member_type_infos.vol.type_name # member type

            # get the member value (pointer or basic)
            member_value = getattr(obj, member_name) # member value
            member_addr = NodeAddr(member_value)

            self.__add_node_wrapper(member_addr, _get_display_name(member_value))

            # create the edge
            self.__add_edge_wrapper(
                parent_addr, 
                member_addr, 
                label=f"{member_name}({member_type})"
            )

            # recursive call
            self._generate_graph_rec(member_value, member_addr)

    def _generate_pointer_graph(self, obj : Pointer, parent_addr : NodeAddr):
        """
        follow a pointer and generate the struct associated
        """
        if not _is_pointer(obj):
            raise Exception("obj is not a pointer")
        
        if not obj.is_readable():
            return
        
        # get the pointer value
        pointer_value = obj.dereference()

        node_addr = NodeAddr(pointer_value)

        node_already_exist = self.__is_node_already_exist(node_addr)

        # add the node
        self.__add_node_wrapper(node_addr, f"{str(pointer_value)}")

        # create the edge
        self.__add_edge_wrapper(
            parent_addr, 
            node_addr, 
            label=f"point to"
        )

        # recursive call
        if not node_already_exist:
            self._generate_graph_rec(pointer_value, node_addr)



    # ---------------------------- wraper ----------------------------

    def __add_node_wrapper(self, addr : NodeAddr, label : str):
        converted_addr = str(addr)
        if not self.__is_node_already_exist(addr):
            self._graph.node(converted_addr, label)
            self._nodes_addr.append(converted_addr)

    def __add_edge_wrapper(self, addr1 : NodeAddr, addr2 : NodeAddr, label : str):
        converted_addr1 = str(addr1)
        converted_addr2 = str(addr2)

        self._graph.edge(
            converted_addr1, 
            converted_addr2, 
            addr1.node_type.value + "->" + label
        )

    # ---------------------------- utils ----------------------------
    def __is_node_already_exist(self, addr : NodeAddr) -> bool:
        return str(addr) in self._nodes_addr
    
    
def _is_struct(obj : ObjectInterface) -> bool:
    """
    check if the object is a struct
    """
    return (
        isinstance(obj, StructType)
    )

def _is_pointer(obj : ObjectInterface) -> bool:
    """
    check if the object is a pointer
    """
    return (
        isinstance(obj, Pointer)
    )

    
def _get_struct_members(obj : ObjectInterface) -> dict[str, tuple[int, Template]]:
    """
    get the members of a struct, theyr offset and theyr type
    """
    if (
        (hasattr(obj.vol, "members")) and 
        (obj.vol.members is not None)
    ):
        return obj.vol.members
    else:
        return {}


def _get_display_name(obj : ObjectInterface) -> str:
    """
    get the display name of an object
    """
    if _is_pointer(obj):
        return f"pointer({obj})"
    elif _is_struct(obj):
        return str(obj)
    else:
        return str(obj)


