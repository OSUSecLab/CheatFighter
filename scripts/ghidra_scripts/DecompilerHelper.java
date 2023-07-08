import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;

public class DecompilerHelper {
    private static DecompilerHelper instance = null;
    private DecompInterface decompInterface;
    private HashMap<Function, HighFunction> decompiled;
    private TaskMonitor monitor;

    private DecompilerHelper(Program program, TaskMonitor monitor) {
        this.decompInterface = setUpDecompiler(program);
        this.decompiled = new HashMap<>();
        this.monitor = monitor;
    }

    public static DecompilerHelper getInstance(Program program, TaskMonitor monitor) {
        if (instance == null) {
            instance = new DecompilerHelper(program, monitor);
        }
        return instance;
    }

    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");
        decompInterface.openProgram(program);
        return decompInterface;
    }

    public HighFunction decompile(Function function) {
        if (function == null) {
            throw new RuntimeException("Function can not be null for decompiling");
        }
        HighFunction highFunction = decompiled.get(function);
        if (highFunction == null) {
            highFunction = decompInterface.decompileFunction(function, 30, monitor).getHighFunction();
            decompiled.put(function, highFunction);
        }
        return highFunction;
    }
}
