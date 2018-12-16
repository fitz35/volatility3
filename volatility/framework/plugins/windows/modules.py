from typing import List

from volatility.framework import constants
from volatility.framework import exceptions, interfaces
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class Modules(interfaces.plugins.PluginInterface):
    """Lists the loaded kernel modules"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")
        ]

    def _generator(self):
        for mod in self.list_modules(self.context, self.config['primary'], self.config['nt_symbols']):

            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                FullDllName = mod.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                FullDllName = ""

            yield (0, (
                format_hints.Hex(mod.vol.offset),
                format_hints.Hex(mod.DllBase),
                format_hints.Hex(mod.SizeOfImage),
                BaseDllName,
                FullDllName,
            ))

    @classmethod
    def list_modules(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str):
        """Lists all the modules in the primary layer"""

        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        try:
            # use this type if its available (starting with windows 10)
            ldr_entry_type = ntkrnlmp.get_type("_KLDR_DATA_TABLE_ENTRY")
        except exceptions.SymbolError:
            ldr_entry_type = ntkrnlmp.get_type("_LDR_DATA_TABLE_ENTRY")

        type_name = ldr_entry_type.type_name.split(constants.BANG)[1]

        list_head = ntkrnlmp.get_symbol("PsLoadedModuleList").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ldr_entry_type.relative_child_offset("InLoadOrderLinks")
        module = ntkrnlmp.object(type_name = type_name, offset = list_entry.vol.offset - reloff)

        for mod in module.InLoadOrderLinks:
            yield mod

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex), ("Name", str), ("Path", str)], self._generator())