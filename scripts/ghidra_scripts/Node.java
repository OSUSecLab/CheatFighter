import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

public class Node {
    private Program program;
    private Boolean stackOffset;
    private Varnode varnode;
    private LinkedList<Address> backtrace;
    private PrintWriter printWriter;
    private String baseName;
    private Map<Set<Varnode>, String> bases;
    private Map<Varnode, String> storedBases;
    private Utility utility;
    private Integer currentVersion;
    private Map<Integer, NodeState> allVersions;
    private Varnode lastOffset;
    private Varnode lastDereference;
    private Set<String> writes;
    private MemoryAccessGraph memoryAccessGraph;

    public Node(Varnode varnode, Program program) {
        this(varnode, new LinkedList<>(), program);
    }

    public Node(Varnode varnode, Node node) {
        this(varnode, new LinkedList<>(node.getBacktrace()), node.getProgram());
    }

    public Node(Varnode varnode, LinkedList<Address> backtrace, Program program) {
        if (varnode == null) {
            throw new RuntimeException("varnode can not be null for creating node");
        }
        this.varnode = varnode;
        this.printWriter = null;
        this.bases = new HashMap<>();
        this.baseName = null;
        this.utility = Utility.getInstance();
        this.storedBases = new HashMap<>();
        this.backtrace = backtrace;
        this.currentVersion = 0;
        this.allVersions = new HashMap<>();
        this.program = program;
        this.writes = new HashSet<>();
        this.stackOffset = false;
    }

    public Map<Set<Varnode>, String> getBases() {
        return bases;
    }

    private void setBases(Map<Set<Varnode>, String> bases) {
        this.bases = bases;
    }

    public Map<Integer, NodeState> getAllVersions() {
        return allVersions;
    }

    public String getBaseName() {
        return baseName;
    }

    public void setBaseName(String baseName) {
        this.baseName = baseName;
        try {
            initializeFileWriter();
            this.memoryAccessGraph = new MemoryAccessGraph(baseName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Node getInstance() {
        Node result = new Node(varnode, this);
        return result;
    }

    public Program getProgram() {
        return program;
    }

    public Integer saveState() {
        NodeState state = new NodeState(getBases(), getStoredBases());
        allVersions.put(currentVersion, state);
        currentVersion++;
        return currentVersion - 1;
    }

    public void restoreState(Integer version) {
        NodeState state = allVersions.get(version);
        if (state != null) {
            saveState();
            setBases(state.getBases());
            setStoredBases(state.getStoredBases());
//            allVersions.remove(version);
        }
    }

    public Map<Varnode, String> getStoredBases() {
        return storedBases;
    }

    private void setStoredBases(Map<Varnode, String> storedBases) {
        this.storedBases = storedBases;
    }

    public Varnode getVarnode() {
        return varnode;
    }

    public void setVarnode(Varnode varnode) {
        this.varnode = varnode;
    }

    public LinkedList<Address> getBacktrace() {
        return new LinkedList<>(backtrace);
    }

    public void addFirst(Address address) {
        if (!this.backtrace.contains(address)) {
            this.backtrace.addFirst(address);
        }
    }

    public void addLast(Address address) {
        if (!this.backtrace.contains(address)) {
            this.backtrace.addLast(address);
        }
    }

    public Address getLast() {
        return this.backtrace.getLast();
    }

    public Address getFirst() {
        return this.backtrace.getFirst();
    }

    @Override
    public String toString() {
        return this.varnode.toString() + " : " + Arrays.toString(backtrace.toArray());
    }

    public void addOffset(List<Varnode> offsets, Address offsetSite, Varnode base, Varnode output) {
        if (offsets == null) {
            return;
        }
        if (baseName == null) {
            throw new RuntimeException("Base name must be set before adding offset to node");
        }

        printWriter.println("++++++++++++++++++++ " + offsetSite + ": " + base.toString() + " Adding Offsets: " + Arrays.toString(offsets.toArray()) + "+++++++++++++++++++");
        printBases("before offset");
        Map<Set<Varnode>, String> newValues = new HashMap<>();
        Set<Varnode> key = null;
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            StringBuilder value = new StringBuilder();
            if (entry.getKey() != null && utility.contains(entry.getKey(), base)) {
                Set<Varnode> newKey = new HashSet<>();
                key = entry.getKey();
                key.add(base);
                value.append(entry.getValue());
                String toBeAdded = addOffsetValuesToString(offsets, value);
                newKey.add(output);
                String result = value.substring(0, value.length() - 2) + "]";
                memoryAccessGraph.addOffset(entry.getValue(), result, toBeAdded);
                newValues.put(newKey, result);
            }
        }
        bases.putAll(newValues);
        if (key == null) {
            StringBuilder value = new StringBuilder();
            key = new HashSet<>();
            key.add(output);
            value.append(baseName);
            String toBeAdded = addOffsetValuesToString(offsets, value);
            String result = value.substring(0, value.length() - 2) + "]";
            memoryAccessGraph.addOffset(baseName, result, toBeAdded);
            bases.put(key, result);
        }
        lastOffset = new Varnode(output.getAddress(), output.getSize());
        printBases("after offset");
    }

    private String addOffsetValuesToString(List<Varnode> offsets, StringBuilder valueParam) {
        StringBuilder value = new StringBuilder();
        value.append(" + [");
        for (Varnode offset : offsets) {
            if (offset.isConstant()) {
                value.append(utility.toHexString(offset.getOffset(), 7));
            } else if (offset.isAddress()) {
                String s = utility.toHexString(offset.getAddress().getOffset());
                Address physicalAddress = program.getAddressFactory().getAddress("ram:" + s);
                Data dataAt = program.getListing().getDataAt(physicalAddress);
                if (dataAt == null) {
                    value.append(varnode.getAddress());
                } else {
                    value.append(dataAt.getValue());
                }
            } else {
                value.append("***").append(offset.toString()).append("***");
                stackOffset = true;
            }
            value.append(" + ");
        }
        valueParam.append(value);
        String s = value.substring(0, value.length() - 2) + "]";
        return s;
    }

    private void initializeFileWriter() throws IOException {
        try {
            if (baseName == null) {
                throw new RuntimeException("Base name must be set before adding offset to node");
            }
            String trace_file_name = baseName.replaceAll("[\\\\/:*?\"<>|%]", "_");
//            System.out.println("");
            File file = new File("C:\\Users\\Asus\\ghidra_scripts\\result\\base_trace_" + trace_file_name);
            FileWriter fileWriter = new FileWriter(file);
            printWriter = new PrintWriter(fileWriter, true);
        } catch (IOException e) {
            FileWriter fileWriter = new FileWriter(new File("C:\\Users\\Asus\\ghidra_scripts\\result\\base_trace"), true);
            printWriter = new PrintWriter(fileWriter, true);
        }
    }

    public void replace(List<Varnode> inputs, List<Varnode> outputs, Address replacingSite) {
        for (Varnode input : inputs) {
            replace(input, outputs, replacingSite);
        }
    }

    public void replace(Varnode input, List<Varnode> outputs, Address replacingSite) {
        printWriter.println("%%%%%%%% " + replacingSite + ": Replacing: " + input.toString() + "->" + Arrays.toString(outputs.toArray()));
        if (utility.varnodeEquals(input, lastOffset)) {
            if (outputs.size() == 1) {
                lastOffset = outputs.get(0);
            } else {
                for (Varnode output : outputs) {
                    if (output.isRegister()) {
                        lastOffset = output;
                        break;
                    }
                }
            }
        }
        if (updateStoredBases(input, outputs)) {
            printBases("after replacing");
            return;
        }

        Set<Set<Varnode>> sets = bases.keySet();
        Set<Varnode> target = null;
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            if (utility.contains(entry.getKey(), input)) {
                target = entry.getKey();
                entry.getKey().addAll(outputs);
            }
        }

        for (Set<Varnode> set : sets) {
            if (!set.equals(target)) {
                Set<Varnode> toBeRemoved = new HashSet<>();
                Set<Varnode> outputSet = new HashSet<>(outputs);
                for (Varnode s : set) {
                    if (utility.contains(outputSet, s)) {
                        toBeRemoved.add(s);
                    }
                }
                set.removeAll(toBeRemoved);
            }
        }

        removeEmptyBases();


        printBases("after replacing");
    }

    private void removeEmptyBases() {
        Set<Set<Varnode>> sets = bases.keySet();
        List<Set<Varnode>> toBeRemoved = new ArrayList<>();
        for (Set<Varnode> set : sets) {
            if (set.isEmpty()) {
                toBeRemoved.add(set);
            }
        }
        for (Set<Varnode> strings : toBeRemoved) {
            bases.remove(strings);
        }
    }

    private boolean updateStoredBases(Varnode input, List<Varnode> outputs) {
        String targetValue = null;
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            if (utility.contains(entry.getKey(), input)) {
                targetValue = entry.getValue();
            }
        }
        if (input.getAddress().isMemoryAddress() || input.getAddress().isStackAddress()) {
            for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
                entry.getKey().removeAll(outputs);
            }
            for (Map.Entry<Varnode, String> entry : storedBases.entrySet()) {
                if (utility.varnodeEquals(entry.getKey(), input)) {
                    bases.put(new HashSet<>(outputs), entry.getValue());
                }
            }

            return true;
        } else if (outputs.stream().anyMatch(v -> v.getAddress().isMemoryAddress() || v.getAddress().isStackAddress()) && targetValue != null) {
            for (Varnode output : outputs) {
                boolean exists = false;
                for (Map.Entry<Varnode, String> entry : storedBases.entrySet()) {
                    if (utility.varnodeEquals(entry.getKey(), output)) {
                        exists = true;
                        entry.setValue(new String(targetValue));
                    }
                }
                if (!exists) {
                    storedBases.put(output, new String(targetValue));
                }
            }
            return true;
        }
        return false;
    }

    public void closeFile() {
        if (printWriter != null) {
            printWriter.close();
        }
    }

    public MemoryAccessGraph getMemoryAccessGraph() {
        return memoryAccessGraph;
    }

    public void dereference(Varnode input, List<Varnode> outputList) {
        Map<Set<Varnode>, String> newValues = new HashMap<>();
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            String value;
            if (entry.getKey() != null && utility.contains(entry.getKey(), input)) {
                value = new String(entry.getValue());
                value = "*(" + value + ")";
                memoryAccessGraph.dereference(entry.getValue(), value);
                Set<Varnode> newKey = new HashSet<>();
                for (Varnode output : outputList) {
                    if (output.getAddress().isMemoryAddress() || output.getAddress().isStackAddress()) {
                        if (storedBases.containsKey(output)) {
                            storedBases.replace(output, value);
                        } else {
                            storedBases.put(output, value);
                        }
                    } else {
                        newKey.add(output);
                    }
                }
                if (!newKey.isEmpty()) {
                    lastDereference = input;
                    newValues.put(newKey, value);
                }
            }
            entry.getKey().removeAll(outputList);
        }
        bases.putAll(newValues);
        if (input != null) {
            printWriter.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Dereference: " + input.getAddress().toString());
        }
        printBases("after dereference");
        removeEmptyBases();
    }


    private void printBases(String prefix) {
        printWriter.println("**********************" + prefix + "*************************");
        for (Map.Entry<Set<Varnode>, String> key : bases.entrySet()) {
            if (!key.getKey().isEmpty()) {
                printWriter.println(Arrays.toString(key.getKey().toArray()) + " : " + key.getValue());
            }
        }
        printWriter.println("-------------------------------------------------------------------");
        for (Map.Entry<Varnode, String> key : storedBases.entrySet()) {
            if (key.getKey() != null) {
                printWriter.println(key.getKey() + " : " + key.getValue());
            }
        }
        printWriter.println("***********************************************");
    }

    public boolean contains(Address fromAddress) {
        for (Address address : backtrace) {
            if (address.equals(fromAddress)) {
                return true;
            }
        }
        return false;
    }

    /*public void dereference(List<Varnode> outputList) {
        for (Varnode output : outputList) {
            dereference(output);
        }
    }*/


    public void removeAll(Set<Varnode> stackVariables) {
        for (Set<Varnode> base : bases.keySet()) {
            base.removeAll(stackVariables);
        }
        removeEmptyBases();
    }

    public void removeUniques() {
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            List<Varnode> uniques = new ArrayList<>();
            for (Varnode s : entry.getKey()) {
                if (s.isUnique()) {
                    uniques.add(s);
                }
            }
            entry.getKey().removeAll(uniques);
        }
        removeEmptyBases();
    }

    public void write(Varnode input) {
        String value = null;
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            if (entry.getKey() != null && entry.getKey().contains(input)) {
                writes.add(entry.getValue());
            }
        }
    }

    public Set<String> getWrites() {
        return writes;
    }

    public Varnode getLastOffset() {
        return lastOffset;
    }

    public Varnode getLastDereference() {
        return lastDereference;
    }

    public void mergeAllVersion() {
        Map<Set<Varnode>, String> allVersionBases = new HashMap<>();
        Map<Varnode, String> allVersionStoredBases = new HashMap<>();
        for (Map.Entry<Integer, NodeState> entry : allVersions.entrySet()) {
            Map<Set<Varnode>, String> versionBases = entry.getValue().getBases();
            for (Map.Entry<Set<Varnode>, String> baseEntry : versionBases.entrySet()) {
                if (!baseEntry.getKey().isEmpty()) {
                    if (!this.bases.containsKey(baseEntry.getKey()) || baseEntry.getValue().length() > bases.get(baseEntry.getKey()).length()) {
                        allVersionBases.put(baseEntry.getKey(), baseEntry.getValue());
                    }
                }
            }
            Map<Varnode, String> versionStoredBases = entry.getValue().getStoredBases();
            allVersionStoredBases.putAll(versionStoredBases);
        }
        this.bases.putAll(allVersionBases);
        this.storedBases.putAll(allVersionStoredBases);
    }

    public String getFirstUseAddress() {
        if (backtrace == null || backtrace.isEmpty()) {
            return "could not";
        }
        for (Address address : backtrace) {
            if (address.getAddressSpace().getType() == AddressSpace.TYPE_RAM) {
                return address.toString();
            }
        }
        return "could not";
    }

    public Boolean getStackOffset() {
        return stackOffset;
    }
}