import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class NodeState {
    private Map<Set<Varnode>, String> bases;
    private Map<Varnode, String> storedBases;

    public NodeState(Map<Set<Varnode>, String> bases, Map<Varnode, String> storedBases) {
        this.bases = new HashMap<>();
        for (Map.Entry<Set<Varnode>, String> entry : bases.entrySet()) {
            Set<Varnode> key = new HashSet<>();
            key.addAll(entry.getKey());
            String value = new String(entry.getValue());
            this.bases.put(key, value);
        }
        this.storedBases = new HashMap<>();
        for (Map.Entry<Varnode, String> entry : storedBases.entrySet()) {
            String value = new String(entry.getValue());
            this.storedBases.put(entry.getKey(), value);
        }
    }

    public Map<Set<Varnode>, String> getBases() {
        return bases;
    }

    public void setBases(Map<Set<Varnode>, String> bases) {
        this.bases = bases;
    }

    public Map<Varnode, String> getStoredBases() {
        return storedBases;
    }

    public void setStoredBases(Map<Varnode, String> storedBases) {
        this.storedBases = storedBases;
    }
}
