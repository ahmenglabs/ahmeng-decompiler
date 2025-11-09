import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Decompile extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get output file path from script arguments
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            println("Error: Output file path required as argument");
            return;
        }
        
        File outputPath = new File(args[0]);
        
        // If the path is a directory, create a file inside it
        File outputFile;
        if (outputPath.isDirectory()) {
            String filename = currentProgram.getName() + ".c";
            outputFile = new File(outputPath, filename);
        } else {
            outputFile = outputPath;
        }
        
        println("Decompiling: " + currentProgram.getName());
        println("Output file: " + outputFile.getAbsolutePath());
        
        // Use Ghidra's CppExporter (same as Dogbolt.org)
        CppExporter cppExporter = new CppExporter();
        List<Option> options = new ArrayList<Option>();
        options.add(new Option(CppExporter.CREATE_HEADER_FILE, true));
        cppExporter.setOptions(options);
        cppExporter.setExporterServiceProvider(state.getTool());
        
        // Export the decompiled code
        cppExporter.export(outputFile, currentProgram, null, monitor);
        
        println("Decompilation completed successfully");
    }
}