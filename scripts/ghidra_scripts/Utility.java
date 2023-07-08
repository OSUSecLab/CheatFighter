import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class Utility {
    private static Utility instance = null;
    private int spOffset = 0x8;

    private Utility(int spOffset) {
        this.spOffset = spOffset;
    }

    public static Utility getInstance() {
        if (instance == null) {
            throw new RuntimeException("Utility has not been initialized before using");
        }
        return instance;
    }

    public static Utility getInstance(Program currentProgram) {
        if (instance == null) {
            instance = new Utility(currentProgram.getRegister("sp").getOffset());
        }
        return instance;
    }

    private static String zeropad(String s, int len) {
        if (s == null) {
            s = "";
        }

        StringBuffer buffer = new StringBuffer(s);
        int zerosNeeded = len - s.length();

        for (int i = 0; i < zerosNeeded; ++i) {
            buffer.insert(0, '0');
        }

        return buffer.toString();
    }

    public boolean isInput(Varnode input) {
        return input.getHigh() != null && input.getHigh().getSymbol() != null && input.getHigh().getSymbol().isParameter();
    }

    public boolean isGlobal(Varnode input) {
        return input.getHigh() != null && input.getHigh().getSymbol() != null && input.getHigh().getSymbol().isGlobal();
    }

    public Integer getFunctionParameterIndex(Varnode varnode) {
        if (varnode.getHigh() == null) {
            throw new RuntimeException("Could not get high variable for input parameter" + varnode.toString());
        }
        if (varnode.getHigh().getSymbol() == null) {
            throw new RuntimeException("Could not get high symbol for input parameter" + varnode.toString());
        }
        return varnode.getHigh().getSymbol().getCategoryIndex();
    }

    public Address getFunctionEntry(Varnode varnode) {
        return varnode.getHigh().getHighFunction().getFunction().getEntryPoint();
    }

    public PcodeOpAST getCallPCodeAST(HighFunction calleeHighFunction, Address callSite) {
        if (calleeHighFunction == null) {
            throw new RuntimeException("Callee High Function can not be null for getting call pcode ast");
        }
        Iterator<PcodeOpAST> pcodeOps = calleeHighFunction.getPcodeOps(callSite);
        PcodeOpAST result = null;
        while (pcodeOps != null && pcodeOps.hasNext()) {
            PcodeOpAST next = pcodeOps.next();
            if (next.getOpcode() == PcodeOp.CALL) {
                result = next;
                break;
            }
        }
        return result;
    }

    public boolean isStackPointer(Varnode input) {
        return input != null && input.isRegister() && input.getOffset() == spOffset;
    }

    public Address getNextInstructionAddress(Program program, Address address) {
        if (address == null) {
            throw new RuntimeException("Address can not be null for getting next instruction address");
        }
        Instruction ins = program.getListing().getInstructionAt(address);
        if (ins == null) {
            return null;
        }
        Instruction nextInstruction = ins.getNext();
        if (nextInstruction == null) {
            return null;
        }
        return nextInstruction.getAddress();
    }

    public Function getFunctionFromCallPCode(PcodeOp callPCode, Program program) {
        if (callPCode == null) {
            throw new RuntimeException("Call pcode ast null for getting function name");
        }
        if (callPCode.getOpcode() != PcodeOp.CALL) {
            throw new RuntimeException("PCode is not call type for getting function name from pcode");
        }
        Address functionEntryPoint = callPCode.getInput(0).getAddress();
        Function result = program.getFunctionManager().getFunctionAt(functionEntryPoint);
        if (result == null) {
            throw new RuntimeException("No function found at address: " + functionEntryPoint);
        }
        return result;
    }

    public Varnode convertAstToVarnode(Varnode varnode) {
        if (varnode == null) {
            return varnode;
        }
        if (varnode instanceof VarnodeAST) {
            varnode = new Varnode(varnode.getAddress(), varnode.getSize());
        }
        return varnode;
    }

    public Set<Varnode> getNonInputStackVariables(Set<Varnode> input) {
        Set<Varnode> stackVariables = new HashSet<>();
        for (Varnode varnode : input) {
            if (varnode != null && varnode.getAddress().isStackAddress() && !isInput(varnode)) {
                stackVariables.add(varnode);
            }
        }
        return stackVariables;
    }

    public String toHexString(long l, int len) {
        String s = Long.toHexString(l);
        s = zeropad(s, len);
        return "0x" + s;
    }

    public String toHexString(long l) {
        String s = Long.toHexString(l);
        s = zeropad(s, 16);
        return "0x" + s;
    }

    public boolean contains(List<Varnode> haystack, Varnode needle) {
        return contains(new HashSet<>(haystack), needle);
    }

    public boolean contains(Set<Varnode> haystack, Varnode needle) {
        if (needle == null) {
            return false;
        }
        if (haystack == null || haystack.isEmpty()) {
            return false;
        }
        for (Varnode varnode : haystack) {
            if (needle == varnode) {
                return true;
            } else if (varnode != null && varnode.getOffset() == needle.getOffset() && varnode.getSpace() == needle.getSpace()) {
                return true;
            }
        }
        return false;
    }

    public boolean varnodeEquals(Varnode v1, Varnode v2) {
        if (v1 == null || v2 == null) {
            return false;
        }
        if (v1 == v2) {
            return true;
        } else return v1.getOffset() == v2.getOffset() && v1.getSpace() == v2.getSpace();
    }

    public Set<Varnode> getNonInputStackVariables(List<Varnode> result) {
        return getNonInputStackVariables(new HashSet<>(result));
    }

    public Address getPreviousInstructionAddress(Program program, Address currentAddress) {
        Instruction instructionBefore = program.getListing().getInstructionBefore(currentAddress);
        if (instructionBefore == null) {
            throw new RuntimeException("Could not get address of instruction before this");
        }
        return instructionBefore.getAddress();
    }

    public void removeFromSet(Set<Varnode> set, Varnode tobeRemoved) {
        Set<Varnode> setTobeRemoved = new HashSet<>();
        for (Varnode varnode : set) {
            if (varnodeEquals(varnode, tobeRemoved)) {
                setTobeRemoved.add(varnode);
            }
        }
        set.removeAll(setTobeRemoved);
    }

    public Data getDataAt(Program program, Address address) {
        Data data = program.getListing().getDefinedDataContaining(address);
        while (data != null && data.isPointer()) {
            Address dataAddress = program.getAddressFactory().getAddress("ram:0x" + data.getValue().toString());
            if (dataAddress == null) {
                break;
            } else {
                data = program.getListing().getDefinedDataAt(dataAddress);
            }
        }
        return data;
    }

    public Varnode getFirstRegister(Program program, Address address) {
        if (address == null) {
            throw new RuntimeException("Address can not be null");
        }
        Instruction instructionAt = program.getListing().getInstructionAt(address);
        if (instructionAt == null) {
            System.out.println("Could not get instruction at address: " + address.toString());
            return null;
        }
        PcodeOp[] pcodes = instructionAt.getPcode();
        Varnode output = null;
        for (PcodeOp pcodeOp : pcodes) {
            switch (pcodeOp.getOpcode()) {
                case PcodeOp.COPY:
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_ADD:
                case PcodeOp.LOAD:
                    output = pcodeOp.getOutput();
                    break;
                case PcodeOp.INT_CARRY:
                case PcodeOp.INT_SCARRY:
                case PcodeOp.INT_EQUAL:
                case PcodeOp.INT_SLESS:
                    break;
                default:
                    throw new RuntimeException("Could not get first varnode");
            }
        }
        if (output == null) {
            throw new RuntimeException("Could not get first varnode");
        }
        return output;
    }

    public Set<Varnode> copyList(Set<Varnode> interestingVarnodes) {
        Set<Varnode> result = new HashSet<>();
        for (Varnode interestingVarnode : interestingVarnodes) {
            result.add(interestingVarnode);
        }
        return result;
    }
}
