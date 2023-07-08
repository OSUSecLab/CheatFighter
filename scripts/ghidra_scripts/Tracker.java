import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Tracker {
    private static Tracker instance = null;

    private static Program program;
    private static Set<String> functions, bfunctions;
    private static Set<Instruction> instructions;
    private static Integer pcodeTracked, functionTracked, instructionTracked, indirectDataAnalyzed, nodes, height, branch;
    private static Integer bpcodeTracked, bfunctionTracked, binstructionTracked;

    private Tracker(Program program) {
        Tracker.program = program;
        functions = new HashSet<>();
        bfunctions = new HashSet<>();
        instructions = new HashSet<>();
        pcodeTracked = 0;
        functionTracked = 0;
        instructionTracked = 0;
        bpcodeTracked = 0;
        bfunctionTracked = 0;
        binstructionTracked = 0;
        indirectDataAnalyzed = 0;
        nodes = 0;
        height = 0;
        branch = 0;
    }

    public static Tracker getInstance(Program program) {
        if (instance == null) {
            instance = new Tracker(program);
        }
        return instance;
    }

    public static void addressTracked(Address address) {
        if (address == null) return;
        instructionTracked++;
        Instruction instructionAt = program.getListing().getInstructionAt(address);
        pcodeTracked += instructionAt.getPcode().length;
        Function functionContaining = program.getFunctionManager().getFunctionContaining(address);
        if (functionContaining == null) return;
        if (!functions.contains(functionContaining.getName())) {
            functions.add(functionContaining.getName());
            functionTracked++;
        }
    }

    public static void setNodes(Set<Node> bases) {
        nodes = 0;
        for (Node base : bases) {
            if (!base.getStackOffset()) {
                List<String> traverse = base.getMemoryAccessGraph().traverse();
                for (String s : traverse) {
                    nodes += getStars(s);
                }
            }
        }
    }

    private static Integer getStars(String s) {
        Integer result = 1;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '*') result++;
        }
        return result;
    }

    public static void pointerTracked() {
        indirectDataAnalyzed++;
    }

    public static Integer getPcodeTracked() {
        return pcodeTracked;
    }

    public static Integer getFunctionTracked() {
        return functionTracked;
    }

    public static Integer getInstructionTracked() {
        return instructionTracked;
    }

    public static Integer getBpcodeTracked() {
        return bpcodeTracked;
    }

    public static Integer getBfunctionTracked() {
        return bfunctionTracked;
    }

    public static Integer getBinstructionTracked() {
        return binstructionTracked;
    }

    public static Integer getIndirectDataAnalyzed() {
        return indirectDataAnalyzed;
    }

    public static void addPCodeTracked() {
        pcodeTracked++;
    }

    public static Integer getNodes() {
        return nodes;
    }

    public static Integer getHeight() {
        return height;
    }

    public static void setHeight(Integer h) {
        if (h > height) {
            height = h;
        }
    }

    public static Integer getBranch() {
        return branch;
    }

    public static void setBranch(Integer b) {
        branch += b;
    }

    public static void baddressTracked(Address address) {
//        System.out.println(address);
        if (address == null) return;
        binstructionTracked++;
        Instruction instructionAt = program.getListing().getInstructionAt(address);
        bpcodeTracked += instructionAt.getPcode().length;
        Function functionContaining = program.getFunctionManager().getFunctionContaining(address);
        if (functionContaining == null) return;
        if (!bfunctions.contains(functionContaining.getName())) {
            bfunctions.add(functionContaining.getName());
            bfunctionTracked++;
        }
    }
}
