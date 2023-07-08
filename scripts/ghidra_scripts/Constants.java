import ghidra.program.model.pcode.PcodeOp;

import java.util.Arrays;
import java.util.List;

public interface Constants {
    public static final String ERROR_PREFIX = "[-] ";
    public static final String SUCCESS_PREFIX = "[+] ";
    public static final String INFO_PREFIX = "[*]\t";
    public static int spOffset = 0x8;
    public static final List<String> ignoredSystemCall = Arrays.asList(
            "fclose",
            "usleep",
            "memset",
            "printf",
            "fputs",
            "__assert2",
            "fflush",
            "feof",
            "free",
            "malloc",
            "puts",
            "close",
            "sleep",
            "fseek",
            "lseek",
            "strchr",
            "exit",
            "select",
            "system",
            "strlen",
            "send",
            "posix_memalign",
            "__stack_chk_fail",
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
            "ptrace",
            "waitpid",
            "perror",
            "memcpy",
            "__android_log_print",
            "pthread_once");
    public static final List<Integer> ignoreList = Arrays.asList(PcodeOp.INT_CARRY,
            PcodeOp.INT_SCARRY,
            PcodeOp.INT_EQUAL,
            PcodeOp.INT_SLESS,
            PcodeOp.INT_SLESSEQUAL,
            PcodeOp.INT_NOTEQUAL,
            PcodeOp.INT_SBORROW,
            PcodeOp.INT_LESSEQUAL,
            PcodeOp.FLOAT_LESS,
            PcodeOp.FLOAT_LESSEQUAL,
            PcodeOp.FLOAT_EQUAL,
            PcodeOp.BOOL_NEGATE,
            PcodeOp.BOOL_AND,
            PcodeOp.BOOL_OR,
            PcodeOp.BOOL_XOR,
            PcodeOp.FLOAT_NAN,
            PcodeOp.CALLOTHER,
            PcodeOp.CALLIND);
}
