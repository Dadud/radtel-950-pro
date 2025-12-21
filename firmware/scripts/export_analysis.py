#@category AT32/Export
#@name Export Firmware Analysis
#@description Export complete firmware analysis to files
# Ghidra Jython script for headless export

from ghidra.app.util.exporter import CppExporter
from ghidra.app.util.exporter import AsciiExporter
from ghidra.app.util.exporter import BinaryExporter
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File

# Get current program
prog = currentProgram
monitor = ConsoleTaskMonitor()

# Export directory
export_dir = File(prog.getExecutablePath()).getParent() + "/analysis_export"
export_file = File(export_dir)
export_file.mkdirs()

print("Exporting to: " + export_dir)

# Export C/C++ code
print("Exporting C/C++ code...")
cpp_exporter = CppExporter()
cpp_file = File(export_dir, prog.getName() + ".c")
cpp_exporter.export(cpp_file, prog, prog.getMemory(), monitor)

# Export symbols/listing
print("Exporting ASCII listing...")
ascii_exporter = AsciiExporter()
ascii_file = File(export_dir, prog.getName() + ".lst")
ascii_exporter.export(ascii_file, prog, prog.getMemory(), monitor)

print("Export complete!")


