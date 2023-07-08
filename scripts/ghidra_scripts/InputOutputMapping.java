import java.util.ArrayList;
import java.util.List;

public enum InputOutputMapping {
    closedir(0, true),
    atoi(0, true),
    open(0, true),
    fopen(0, true),
    strtok(0, true),
    strtoul(0, true),
    opendir(0, true),
    readdir(0, true),
    strcat(1, true),
    snprintf(2, 0),
    sprintf(-1, 0),
    fgets(2, 0),
    sscanf(0, -2),
    fscanf(1, -2),
    write(1, -2),
    strstr(List.of(0, 1), false),
    feof(false),
    strcasestr(List.of(0, 1), false),
    strcmp(List.of(0, 1), false),
    strncmp(List.of(0, 1), false),
    read(0, 2),
    pread64(3, 1),
    pwrite64(List.of(1, 3), List.of(0)),
    vsnprintf(List.of(2,3), List.of(0)),
    memcpy(0, 1),
    syscall(1, 1),
    fclose(false),
    usleep(false),
    memset(false),
    printf(false),
    fputs(false),
    __assert2(false),
    fflush(false),
    free(false),
    malloc(false),
    puts(false),
    close(false),
    sleep(false),
    fseek(false),
    lseek(false),
    strchr(false),
    exit(false),
    select(false),
    system(false),
    strlen(false),
    send(false),
    posix_memalign(false),
    __stack_chk_fail(false),
    pthread_mutex_lock(false),
    pthread_mutex_unlock(false),
    ptrace(false),
    waitpid(false),
    perror(false),
    __android_log_print(false),
    pthread_once(false),
    ;

    private final List<Integer> inputIndices;
    private final List<Integer> outputIndices;
    private final boolean dataFlowing;

    InputOutputMapping(List<Integer> inputIndices, boolean dataFlowing) {
        this.inputIndices = inputIndices;
        this.outputIndices = new ArrayList<>();
        this.dataFlowing = dataFlowing;
    }

    InputOutputMapping(Integer inputIndex, boolean dataFlowing) {
        this.inputIndices = List.of(inputIndex);
        this.outputIndices = new ArrayList<>();
        this.dataFlowing = dataFlowing;
    }

    InputOutputMapping(boolean dataFlowing) {
        this.inputIndices = new ArrayList<>();
        this.outputIndices = new ArrayList<>();
        this.dataFlowing = dataFlowing;
    }

    InputOutputMapping(Integer inputIndex, Integer outputIndex) {
        this.inputIndices = List.of(inputIndex);
        this.outputIndices = List.of(outputIndex);
        this.dataFlowing = true;
    }

    InputOutputMapping(List<Integer> inputs, List<Integer> outputs) {
        this.inputIndices = inputs;
        this.outputIndices = outputs;
        this.dataFlowing = true;
    }

    public List<Integer> getInputIndices() {
        return inputIndices;
    }

    public boolean flowsToOutput() {
        return outputIndices.isEmpty();
    }

    public boolean multipleOutput() {
        return outputIndices.size() == 1 && outputIndices.get(0) < 0;
    }

    public Integer getMultipleOutputStart() {
        if (multipleOutput()) {
            return -1 * outputIndices.get(0);
        }
        throw new RuntimeException("Called for multiple output start for non multiple output system call");
    }

    public Integer getSingleInput() {
        if (inputIndices.size() == 1) {
            return inputIndices.get(0);
        }
        throw new RuntimeException("Called for getting single input for system calls with multiple inputs");
    }

    public List<Integer> getOutputIndices() {
        return outputIndices;
    }

    public boolean isDataFlowing() {
        return dataFlowing;
    }

    public boolean multipleInput() {
        return inputIndices.size() == 1 && inputIndices.get(0) < 0;
    }

    public Integer getMultipleInputStart() {
        if (multipleInput()) {
            return -1 * inputIndices.get(0);
        }
        throw new RuntimeException("Called for getting multiple input start with non multiple mapping");
    }
}
