//@category AT32/Export
//@menupath Tools.AT32.Export All Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;

public class export_all extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        // Get export directory based on executable path
        String basePath = currentProgram.getExecutablePath();
        File exeFile = new File(basePath);
        String parentDir = exeFile.getParent();
        String exportDir = parentDir + File.separator + "analysis_export";
        File exportFolder = new File(exportDir);
        exportFolder.mkdirs();
        
        println("Exporting to: " + exportDir);
        
        // Export C/C++ code
        println("Exporting C/C++ code...");
        CppExporter cppExporter = new CppExporter();
        File cppFile = new File(exportDir, currentProgram.getName() + ".c");
        cppExporter.export(cppFile, currentProgram, currentProgram.getMemory(), new ConsoleTaskMonitor());
        
        // Export ASCII listing
        println("Exporting ASCII listing...");
        AsciiExporter asciiExporter = new AsciiExporter();
        File asciiFile = new File(exportDir, currentProgram.getName() + ".lst");
        asciiExporter.export(asciiFile, currentProgram, currentProgram.getMemory(), new ConsoleTaskMonitor());
        
        println("Export complete! Files saved to: " + exportDir);
    }
}
