import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import java.io.*;
import java.util.*;

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

        StringBuilder decompiledCode = new StringBuilder();
        
        // ==== BINARY METADATA ====
        decompiledCode.append("/*\n");
        decompiledCode.append("================================================================================\n");
        decompiledCode.append("BINARY ANALYSIS REPORT - CTF Edition\n");
        decompiledCode.append("================================================================================\n");
        decompiledCode.append("File: ").append(filename).append("\n");
        decompiledCode.append("Architecture: ").append(currentProgram.getLanguage().getProcessor()).append("\n");
        decompiledCode.append("Endian: ").append(currentProgram.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        decompiledCode.append("Compiler: ").append(currentProgram.getCompiler()).append("\n");
        decompiledCode.append("Executable Format: ").append(currentProgram.getExecutableFormat()).append("\n");
        decompiledCode.append("Image Base: ").append(currentProgram.getImageBase()).append("\n");
        
        // ==== SECURITY PROTECTIONS ====
        decompiledCode.append("\n--- Security Protections ---\n");
        decompiledCode.append("Relocatable: ").append(currentProgram.getRelocationTable().getSize() > 0 ? "Yes (PIE)" : "No").append("\n");
        
        // Check for stack canary
        boolean hasCanary = false;
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(false);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName().toLowerCase();
            if (name.contains("stack_chk") || name.contains("canary")) {
                hasCanary = true;
                break;
            }
        }
        decompiledCode.append("Stack Canary: ").append(hasCanary ? "Yes" : "No/Unknown").append("\n");
        
        // Check NX bit (usually enabled in modern binaries)
        MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");
        if (textBlock != null) {
            decompiledCode.append("NX (Non-Executable Stack): ").append(textBlock.isExecute() ? "Text is executable" : "Unknown").append("\n");
        }
        
        // ==== ENTRY POINT ====
        decompiledCode.append("\n--- Entry Point ---\n");
        Function entryFunc = currentProgram.getFunctionManager().getFunctionAt(currentProgram.getImageBase().add(currentProgram.getAddressFactory().getDefaultAddressSpace().getMinAddress().getOffset()));
        if (entryFunc == null) {
            // Try to find main function
            SymbolTable symTable = currentProgram.getSymbolTable();
            SymbolIterator mainSyms = symTable.getSymbols("main");
            if (mainSyms.hasNext()) {
                entryFunc = currentProgram.getFunctionManager().getFunctionAt(mainSyms.next().getAddress());
            }
        }
        if (entryFunc != null) {
            decompiledCode.append("Entry Function: ").append(entryFunc.getName()).append(" @ ").append(entryFunc.getEntryPoint()).append("\n");
        } else {
            decompiledCode.append("Entry point: ").append(currentProgram.getImageBase()).append("\n");
        }
        
        // ==== MEMORY SECTIONS ====
        decompiledCode.append("\n--- Memory Sections ---\n");
        for (MemoryBlock block : memory.getBlocks()) {
            decompiledCode.append(String.format("  %s: 0x%s - 0x%s (%d bytes) [%s%s%s]\n",
                block.getName(),
                block.getStart().toString(),
                block.getEnd().toString(),
                block.getSize(),
                block.isRead() ? "R" : "-",
                block.isWrite() ? "W" : "-",
                block.isExecute() ? "X" : "-"
            ));
        }
        
        // ==== IMPORTED FUNCTIONS ====
        decompiledCode.append("\n--- Imported Functions ---\n");
        SymbolIterator extSymbols = symTable.getExternalSymbols();
        Set<String> imports = new TreeSet<>();
        Set<String> dangerousFuncs = new HashSet<>(Arrays.asList(
            "gets", "strcpy", "strcat", "sprintf", "scanf", "vsprintf",
            "system", "exec", "popen", "strcpy", "strncpy", "memcpy",
            "read", "fgets", "getenv", "printf", "fprintf", "snprintf"
        ));
        Set<String> foundDangerous = new TreeSet<>();
        
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                String funcName = sym.getName();
                imports.add(funcName);
                if (dangerousFuncs.contains(funcName)) {
                    foundDangerous.add(funcName);
                }
            }
        }
        if (imports.isEmpty()) {
            decompiledCode.append("No external imports found\n");
        } else {
            for (String imp : imports) {
                String marker = foundDangerous.contains(imp) ? " [DANGEROUS]" : "";
                decompiledCode.append("  - ").append(imp).append(marker).append("\n");
            }
        }
        
        // ==== DANGEROUS FUNCTIONS SUMMARY ====
        if (!foundDangerous.isEmpty()) {
            decompiledCode.append("\n!!! POTENTIAL VULNERABILITIES DETECTED !!!\n");
            decompiledCode.append("Dangerous functions found: ").append(String.join(", ", foundDangerous)).append("\n");
            decompiledCode.append("These functions may lead to: Buffer Overflow, Format String, Command Injection\n");
        }
        
        decompiledCode.append("\n================================================================================\n");
        decompiledCode.append("*/\n\n");

        // Get the decompiler
        ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
        decomp.openProgram(currentProgram);

        // Decompile all functions
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        
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