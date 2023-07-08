import java.util.ArrayList;
import java.util.List;

public class MemoryAccessGraph {
    MemoryAccessNode root;
    Integer height;
    Integer branches;
    List<String> traversal;

    public MemoryAccessGraph(String rootKey) {
        root = new MemoryAccessNode(rootKey);
    }

    public Integer getHeight() {
        return height;
    }

    public Integer getBranches() {
        return branches;
    }

    public void addOffset(String key, String newKey, String toBeAdded) {
        root.addOffset(key, newKey, toBeAdded);
    }

    public void dereference(String key, String newKey) {
        root.dereference(key, newKey);
//        Tracker.newNode();
    }

    @Override
    public String toString() {
        return root.toString();
    }

    public List<String> traverse() {
        if (traversal != null) return traversal;
        List<String> result = new ArrayList<>();
        String rootResult = "";
        height = root.traverse(1, rootResult, result);
        branches = result.size();
        traversal = result;
        return traversal;
    }
}


