from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

class Test(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                            architectures = ["Intel32", "Intel64"])]
    
    def run(self):
        return renderers.TreeGrid([("addr", format_hints.Hex)], self._generator())
    
    def _generator(
        self
    ):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        print("offset:", vmlinux.offset)

        struct_name = "kmem_cache"

        toIterate = [vmlinux.object_from_symbol(symbol_name = struct_name, absolute=True)]

        print(toIterate)
        

        for obj in toIterate:
            for value in obj.vol:
                print(value)

            # list the members of the struct
            print("members : ", obj.vol.subtype.members) # dict of tuple {name : (offset, object)}

            print("obj.cpu_partial : ", obj.cpu_partial)
            
            # no idea what this does
            print("pointer_to_string", utility.pointer_to_string(obj, 10))

            # no idea what this does (list of same type pointer ???)
            try:
                subobjects = utility.array_of_pointers(
                    obj.dereference(),
                    count=obj.vol.subtype.members.__len__(),
                    subtype=vmlinux.symbol_table_name + constants.BANG + struct_name,
                    context=self.context,
                )
            except exceptions.PagedInvalidAddressException:
                continue

            for subobj in subobjects:
                print(subobj.vol.type_name)
                print(subobj.vol.offset)

            # get the offset of the subfield
            kobj_offset = obj.vol.subtype.members["kobj"][0]
            kobj_addr = obj.vol.offset + kobj_offset
            kobj = vmlinux.object(object_type = "kobject", offset = kobj_addr)
            print("kobj offset : ", kobj.vol.offset)
            print("obj addr : ", obj.vol.offset)
            for value in kobj.vol:
                print(value)
                

            yield (0, [format_hints.Hex(obj.vol.offset)])

        