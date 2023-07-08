import java.util.ArrayList;
import java.util.List;

public class MemoryAccessNode {
    private final String key;
    boolean dereferenced;
    List<MemoryAccessNode> children;
    private String extra;

    public MemoryAccessNode(String key) {
        this.key = new String(key);
        this.children = new ArrayList<>();
        this.dereferenced = false;
    }

    public MemoryAccessNode(String key, String extra) {
        this.key = new String(key);
        this.extra = new String(extra);
        this.dereferenced = false;
        this.children = new ArrayList<>();
    }

    public String getKey() {
        return key;
    }

    void addOffset(String key, String newKey, String toBeAdded) {
        if (this.key.equals(key)) {
            for (MemoryAccessNode child : children) {
                if (child.getKey().equals(newKey)) {
                    return;
                }
            }
            this.children.add(new MemoryAccessNode(newKey, toBeAdded));
        } else {
            for (MemoryAccessNode child : children) {
                child.addOffset(key, newKey, toBeAdded);
            }
        }
    }

    void dereference(String key, String newKey) {
        if (this.key.equals(key)) {
            if (dereferenced) return;
            this.dereferenced = true;
            this.children.add(new MemoryAccessNode(newKey, "*"));
        } else {
            for (MemoryAccessNode child : children) {
                child.dereference(key, newKey);
            }
        }
    }

    @Override
    public String toString() {
        String result = extra == null ? new String(key) : new String(extra);
        if (!children.isEmpty()) result += "-------->\n";
        for (MemoryAccessNode child : children) {
            result += child.toString();
        }
        return result;
    }

    public int traverse(int level, String rootResult, List<String> paths) {
        String result = new String(rootResult);
        result += extra == null ? new String(key) : new String(extra);
        if (children.isEmpty()) {
            paths.add(result);
            return level;
        } else {
            int highest = level;
            if (extra != null && extra.equals("*")) {
                highest = level + 1;
                level = level + 1;
            }
            for (MemoryAccessNode child : children) {
                int childHeight = child.traverse(level, result, paths);
                if (childHeight > highest) highest = childHeight;
            }
            return highest;
        }
    }
}