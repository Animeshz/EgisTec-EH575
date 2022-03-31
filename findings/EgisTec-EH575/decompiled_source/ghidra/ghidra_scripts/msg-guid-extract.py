from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

space = currentProgram.getAddressFactory().getDefaultAddressSpace()
symbols = currentProgram.getSymbolTable().getAllSymbols(True)
listing = currentProgram.getListing()
flat_api = FlatProgramAPI(currentProgram)
flat_decompiler_api = FlatDecompilerAPI(flat_api)

trace_message_addr = space.getAddress('0x180023a96')
if not flat_api.getFunctionAt(trace_message_addr):
    print('There is no function TraceMessage at 0x180023a96')
    exit(1)

trace_message = listing.getCodeUnitAt(trace_message_addr)
all_xrefs = getXRefList​(trace_message)

