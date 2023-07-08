import ghidra.program.model.address.Address;

import java.util.Map;

public class StringSearchResult {
    Map<String, Address> mappingStrings;
    Map<String, Address> libraryStrings;

    public StringSearchResult(Map<String, Address> mappingStrings, Map<String, Address> libraryStrings) {
        this.mappingStrings = mappingStrings;
        this.libraryStrings = libraryStrings;
    }

    public Map<String, Address> getMappingStrings() {
        return mappingStrings;
    }

    public Map<String, Address> getLibraryStrings() {
        return libraryStrings;
    }
}
