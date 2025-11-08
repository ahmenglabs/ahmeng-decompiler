import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class Decompile extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputDir = getScriptArgs()[0];
        String filename = currentProgram.getName();

        // Get the decompiler
        ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
        decomp.openProgram(currentProgram);

        // Decompile all functions
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder decompiledCode = new StringBuilder();

        for (Function function : functions) {
            ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(function, 30, null);
            if (results.decompileCompleted()) {
                decompiledCode.append("// Function: ").append(function.getName()).append("\n");
                decompiledCode.append(results.getDecompiledFunction().getC()).append("\n\n");
            }
        }

        // Write to file
        File outputFile = new File(outputDir, filename.replaceAll("\\.[^.]*$", "") + ".c");
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(decompiledCode.toString());
        }

        println("Decompilation completed for " + filename);
    }
}