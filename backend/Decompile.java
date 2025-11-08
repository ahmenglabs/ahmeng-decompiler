import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class Decompile extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get output directory from script arguments, or use current directory
        String outputDir = ".";
        String[] args = getScriptArgs();
        if (args != null && args.length > 0) {
            outputDir = args[0];
        }
        
        String filename = currentProgram.getName();
        println("Decompiling: " + filename);
        println("Output directory: " + outputDir);

        // Get the decompiler
        ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
        decomp.openProgram(currentProgram);

        // Decompile all functions
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder decompiledCode = new StringBuilder();
        
        int functionCount = 0;
        for (Function function : functions) {
            try {
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(function, 30, null);
                if (results.decompileCompleted()) {
                    decompiledCode.append("// Function: ").append(function.getName()).append("\n");
                    decompiledCode.append("// Address: ").append(function.getEntryPoint()).append("\n");
                    decompiledCode.append(results.getDecompiledFunction().getC()).append("\n\n");
                    functionCount++;
                } else {
                    println("Failed to decompile function: " + function.getName());
                }
            } catch (Exception e) {
                println("Error decompiling function " + function.getName() + ": " + e.getMessage());
            }
        }

        decomp.dispose();
        
        // Write to file
        String outputFilename = filename.replaceAll("\\.[^.]*$", "") + "_decompiled.c";
        File outputFile = new File(outputDir, outputFilename);
        
        println("Writing to: " + outputFile.getAbsolutePath());
        
        try (FileWriter writer = new FileWriter(outputFile)) {
            if (decompiledCode.length() > 0) {
                writer.write(decompiledCode.toString());
                println("Successfully wrote " + functionCount + " functions to " + outputFilename);
            } else {
                writer.write("// No functions found to decompile\n");
                println("Warning: No functions found to decompile");
            }
        }

        println("Decompilation completed for " + filename);
    }
}