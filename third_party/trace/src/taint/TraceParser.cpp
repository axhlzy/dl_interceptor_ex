#include "TraceParser.h"
#include <cstring>
#include <algorithm>

// ============================================================
// 安全的 16 进制解析（处理 128-bit 值，截断为 64-bit）
// ============================================================

uint64_t TraceParser::parse_hex_safe(const char* s, int len) {
    uint64_t val = 0;
    // 超过 16 位十六进制时只取低 64 位
    int start = (len > 16) ? (len - 16) : 0;
    for (int i = start; i < len; i++) {
        char c = s[i];
        uint64_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        val = (val << 4) | digit;
    }
    return val;
}

// ============================================================
// 寄存器名解析（手动，无 allocation）
// ============================================================

RegId TraceParser::parse_reg_name(const char* s, int len) {
    if (len <= 0) return REG_INVALID;

    switch (s[0]) {
    case 'x': case 'X':
        if (len == 2 && s[1] >= '0' && s[1] <= '9')
            return (RegId)(REG_X0 + (s[1] - '0'));
        if (len == 3 && s[1] >= '0' && s[1] <= '3' && s[2] >= '0' && s[2] <= '9') {
            int n = (s[1] - '0') * 10 + (s[2] - '0');
            if (n <= 30) return (RegId)(REG_X0 + n);
        }
        if (len == 3 && s[1] == 'z' && s[2] == 'r') return REG_XZR;
        break;
    case 'w': case 'W':
        if (len == 2 && s[1] >= '0' && s[1] <= '9')
            return (RegId)(REG_X0 + (s[1] - '0'));  // w→x 直接归一化
        if (len == 3 && s[1] >= '0' && s[1] <= '3' && s[2] >= '0' && s[2] <= '9') {
            int n = (s[1] - '0') * 10 + (s[2] - '0');
            if (n <= 30) return (RegId)(REG_X0 + n);
        }
        if (len == 3 && s[1] == 'z' && s[2] == 'r') return REG_XZR;
        break;
    case 's':
        if (len == 2 && s[1] == 'p') return REG_SP;
        // s0-s31
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_S0 + n);
        }
        break;
    case 'f':
        if (len == 2 && s[1] == 'p') return REG_FP;
        break;
    case 'l':
        if (len == 2 && s[1] == 'r') return REG_LR;
        break;
    case 'q': case 'Q':
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_Q0 + n);
        }
        break;
    case 'd': case 'D':
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_D0 + n);
        }
        break;
    case 'h': case 'H':
        // h0-h31 → 归一化到 q 系列
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_Q0 + n);
        }
        break;
    case 'b': case 'B':
        // b0-b31 → 归一化到 q 系列
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_Q0 + n);
        }
        // 避免与 branch 指令助记符冲突：b.eq 等不会进入这里（那些是 mnemonic 不是 reg）
        break;
    case 'v': case 'V':
        // v0-v31 → 归一化到 q 系列
        if (len >= 2 && s[1] >= '0' && s[1] <= '9') {
            int n = s[1] - '0';
            if (len == 3 && s[2] >= '0' && s[2] <= '9') n = n * 10 + (s[2] - '0');
            if (n <= 31) return (RegId)(REG_Q0 + n);
        }
        break;
    case 'n':
        if (len == 4 && memcmp(s, "nzcv", 4) == 0) return REG_NZCV;
        break;
    }
    return REG_INVALID;
}

RegId TraceParser::normalize(RegId id) {
    if (id == REG_FP) return (RegId)(REG_X0 + 29);
    if (id == REG_LR) return (RegId)(REG_X0 + 30);
    // q/d/s 寄存器归一化到 q 系列
    if (id >= REG_D0 && id <= REG_D31) return (RegId)(REG_Q0 + (id - REG_D0));
    if (id >= REG_S0 && id <= REG_S31) return (RegId)(REG_Q0 + (id - REG_S0));
    return id;
}

static const char* reg_names[] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28",
    "fp","lr","sp","xzr","nzcv",
    "q0","q1","q2","q3","q4","q5","q6","q7",
    "q8","q9","q10","q11","q12","q13","q14","q15",
    "q16","q17","q18","q19","q20","q21","q22","q23",
    "q24","q25","q26","q27","q28","q29","q30","q31",
    "d0","d1","d2","d3","d4","d5","d6","d7",
    "d8","d9","d10","d11","d12","d13","d14","d15",
    "d16","d17","d18","d19","d20","d21","d22","d23",
    "d24","d25","d26","d27","d28","d29","d30","d31",
    "s0","s1","s2","s3","s4","s5","s6","s7",
    "s8","s9","s10","s11","s12","s13","s14","s15",
    "s16","s17","s18","s19","s20","s21","s22","s23",
    "s24","s25","s26","s27","s28","s29","s30","s31",
};

const char* TraceParser::reg_name(RegId id) {
    if (id == REG_INVALID) return "?";
    if (id < sizeof(reg_names)/sizeof(reg_names[0])) return reg_names[id];
    return "?";
}

// ============================================================
// 指令分类（手动比较，无 std::string）
// ============================================================

static bool mnem_eq(const char* m, int len, const char* target) {
    int tlen = (int)strlen(target);
    return len == tlen && memcmp(m, target, tlen) == 0;
}

InsnCategory TraceParser::classify_mnemonic(const char* m, int len) {
    if (len <= 0) return InsnCategory::OTHER;

    switch (m[0]) {
    case 'm':
        if (mnem_eq(m, len, "mov") || mnem_eq(m, len, "mvn"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "movz") || mnem_eq(m, len, "movn"))
            return InsnCategory::IMM_LOAD;
        if (mnem_eq(m, len, "movk"))
            return InsnCategory::PARTIAL_MODIFY;
        if (mnem_eq(m, len, "mul") || mnem_eq(m, len, "madd") || mnem_eq(m, len, "msub") ||
            mnem_eq(m, len, "mneg"))
            return InsnCategory::ARITHMETIC;
        break;
    case 'n':
        if (mnem_eq(m, len, "neg") || mnem_eq(m, len, "negs") ||
            mnem_eq(m, len, "ngc") || mnem_eq(m, len, "ngcs"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "nop"))
            return InsnCategory::BRANCH;
        break;
    case 'c':
        if (mnem_eq(m, len, "cls") || mnem_eq(m, len, "clz"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "cmp") || mnem_eq(m, len, "cmn") ||
            mnem_eq(m, len, "ccmp") || mnem_eq(m, len, "ccmn"))
            return InsnCategory::COMPARE;
        if (mnem_eq(m, len, "csel") || mnem_eq(m, len, "csinc") ||
            mnem_eq(m, len, "csinv") || mnem_eq(m, len, "csneg") ||
            mnem_eq(m, len, "cset") || mnem_eq(m, len, "csetm") ||
            mnem_eq(m, len, "cinc") || mnem_eq(m, len, "cinv") ||
            mnem_eq(m, len, "cneg"))
            return InsnCategory::COND_SELECT;
        if (mnem_eq(m, len, "cbz") || mnem_eq(m, len, "cbnz"))
            return InsnCategory::BRANCH;
        break;
    case 'a':
        if (mnem_eq(m, len, "add") || mnem_eq(m, len, "adds") ||
            mnem_eq(m, len, "adc") || mnem_eq(m, len, "adcs"))
            return InsnCategory::ARITHMETIC;
        if (mnem_eq(m, len, "and") || mnem_eq(m, len, "ands"))
            return InsnCategory::LOGIC;
        if (mnem_eq(m, len, "adr") || mnem_eq(m, len, "adrp"))
            return InsnCategory::IMM_LOAD;
        if (mnem_eq(m, len, "asr"))
            return InsnCategory::SHIFT_EXT;
        // PAC 认证指令（autiasp, autibsp, autia, autib, autda, autdb）
        if (len >= 5 && memcmp(m, "aut", 3) == 0)
            return InsnCategory::BRANCH;
        break;
    case 's':
        if (mnem_eq(m, len, "sub") || mnem_eq(m, len, "subs") ||
            mnem_eq(m, len, "sbc") || mnem_eq(m, len, "sbcs") ||
            mnem_eq(m, len, "sdiv") || mnem_eq(m, len, "smull") ||
            mnem_eq(m, len, "smulh") || mnem_eq(m, len, "smaddl") ||
            mnem_eq(m, len, "smsubl"))
            return InsnCategory::ARITHMETIC;
        if (mnem_eq(m, len, "str") || mnem_eq(m, len, "strb") ||
            mnem_eq(m, len, "strh") || mnem_eq(m, len, "stur") ||
            mnem_eq(m, len, "sturb") || mnem_eq(m, len, "sturh") ||
            mnem_eq(m, len, "stp") || mnem_eq(m, len, "stlr") ||
            mnem_eq(m, len, "stlrb") || mnem_eq(m, len, "stlrh") ||
            mnem_eq(m, len, "stxr") || mnem_eq(m, len, "stlxr") ||
            mnem_eq(m, len, "stxrb") || mnem_eq(m, len, "stlxrb") ||
            mnem_eq(m, len, "stxrh") || mnem_eq(m, len, "stlxrh") ||
            mnem_eq(m, len, "stxp") || mnem_eq(m, len, "stlxp"))
            return InsnCategory::STORE;
        if (mnem_eq(m, len, "sbfm") || mnem_eq(m, len, "sbfx"))
            return InsnCategory::BITFIELD;
        if (mnem_eq(m, len, "sxtb") || mnem_eq(m, len, "sxth") || mnem_eq(m, len, "sxtw"))
            return InsnCategory::SHIFT_EXT;
        if (mnem_eq(m, len, "scvtf"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "svc"))
            return InsnCategory::BRANCH;
        break;
    case 'l':
        if (mnem_eq(m, len, "ldr") || mnem_eq(m, len, "ldrb") ||
            mnem_eq(m, len, "ldrh") || mnem_eq(m, len, "ldrsw") ||
            mnem_eq(m, len, "ldrsb") || mnem_eq(m, len, "ldrsh") ||
            mnem_eq(m, len, "ldur") || mnem_eq(m, len, "ldurb") ||
            mnem_eq(m, len, "ldurh") || mnem_eq(m, len, "ldursw") ||
            mnem_eq(m, len, "ldursb") || mnem_eq(m, len, "ldursh") ||
            mnem_eq(m, len, "ldp") || mnem_eq(m, len, "ldpsw") ||
            mnem_eq(m, len, "ldar") || mnem_eq(m, len, "ldarb") ||
            mnem_eq(m, len, "ldarh") ||
            mnem_eq(m, len, "ldxr") || mnem_eq(m, len, "ldaxr") ||
            mnem_eq(m, len, "ldxrb") || mnem_eq(m, len, "ldaxrb") ||
            mnem_eq(m, len, "ldxrh") || mnem_eq(m, len, "ldaxrh") ||
            mnem_eq(m, len, "ldxp") || mnem_eq(m, len, "ldaxp") ||
            mnem_eq(m, len, "ldnp") || mnem_eq(m, len, "ldtr") ||
            mnem_eq(m, len, "ldtrb") || mnem_eq(m, len, "ldtrh") ||
            mnem_eq(m, len, "ldtrsw") || mnem_eq(m, len, "ldtrsb") ||
            mnem_eq(m, len, "ldtrsh"))
            return InsnCategory::LOAD;
        if (mnem_eq(m, len, "lsl") || mnem_eq(m, len, "lsr"))
            return InsnCategory::SHIFT_EXT;
        break;
    case 'd':
        if (mnem_eq(m, len, "dmb") || mnem_eq(m, len, "dsb") || mnem_eq(m, len, "dc"))
            return InsnCategory::BRANCH;
        break;
    case 'o':
        if (mnem_eq(m, len, "orr") || mnem_eq(m, len, "orn"))
            return InsnCategory::LOGIC;
        break;
    case 'e':
        if (mnem_eq(m, len, "eor") || mnem_eq(m, len, "eon"))
            return InsnCategory::LOGIC;
        if (mnem_eq(m, len, "extr"))
            return InsnCategory::BITFIELD;
        break;
    case 'f':
        if (mnem_eq(m, len, "fmov"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "fadd") || mnem_eq(m, len, "fsub") ||
            mnem_eq(m, len, "fmul") || mnem_eq(m, len, "fdiv") ||
            mnem_eq(m, len, "fneg") || mnem_eq(m, len, "fabs") ||
            mnem_eq(m, len, "fsqrt") || mnem_eq(m, len, "fmadd") ||
            mnem_eq(m, len, "fmsub") || mnem_eq(m, len, "fnmadd") ||
            mnem_eq(m, len, "fnmsub") || mnem_eq(m, len, "fmin") ||
            mnem_eq(m, len, "fmax") || mnem_eq(m, len, "fnmul"))
            return InsnCategory::ARITHMETIC;
        if (mnem_eq(m, len, "fcmp") || mnem_eq(m, len, "fccmp") ||
            mnem_eq(m, len, "fcmpe") || mnem_eq(m, len, "fccmpe"))
            return InsnCategory::COMPARE;
        if (mnem_eq(m, len, "fcsel"))
            return InsnCategory::COND_SELECT;
        // fcvt 系列、frint 系列 → 数据移动
        if (len >= 4 && memcmp(m, "fcvt", 4) == 0)
            return InsnCategory::DATA_MOVE;
        if (len >= 5 && memcmp(m, "frint", 5) == 0)
            return InsnCategory::DATA_MOVE;
        break;
    case 'i':
        if (mnem_eq(m, len, "isb") || mnem_eq(m, len, "ic"))
            return InsnCategory::BRANCH;
        break;
    case 'b':
        if (mnem_eq(m, len, "bic") || mnem_eq(m, len, "bics"))
            return InsnCategory::LOGIC;
        if (mnem_eq(m, len, "bfm") || mnem_eq(m, len, "bfi") || mnem_eq(m, len, "bfxil"))
            return InsnCategory::BITFIELD;
        if (mnem_eq(m, len, "b") || mnem_eq(m, len, "bl") ||
            mnem_eq(m, len, "br") || mnem_eq(m, len, "blr") ||
            mnem_eq(m, len, "bti"))
            return InsnCategory::BRANCH;
        // b.eq, b.ne, etc.
        if (len >= 2 && m[1] == '.')
            return InsnCategory::BRANCH;
        break;
    case 'r':
        if (mnem_eq(m, len, "ret") || mnem_eq(m, len, "retaa") || mnem_eq(m, len, "retab"))
            return InsnCategory::BRANCH;
        if (mnem_eq(m, len, "rbit") || mnem_eq(m, len, "rev") ||
            mnem_eq(m, len, "rev16") || mnem_eq(m, len, "rev32") ||
            mnem_eq(m, len, "rev64"))
            return InsnCategory::DATA_MOVE;
        if (mnem_eq(m, len, "ror"))
            return InsnCategory::SHIFT_EXT;
        break;
    case 'u':
        if (mnem_eq(m, len, "udiv") || mnem_eq(m, len, "umull") ||
            mnem_eq(m, len, "umulh") || mnem_eq(m, len, "umaddl") ||
            mnem_eq(m, len, "umsubl"))
            return InsnCategory::ARITHMETIC;
        if (mnem_eq(m, len, "ubfm") || mnem_eq(m, len, "ubfx"))
            return InsnCategory::BITFIELD;
        if (mnem_eq(m, len, "uxtb") || mnem_eq(m, len, "uxth"))
            return InsnCategory::SHIFT_EXT;
        if (mnem_eq(m, len, "ucvtf"))
            return InsnCategory::DATA_MOVE;
        break;
    case 't':
        if (mnem_eq(m, len, "tst"))
            return InsnCategory::COMPARE;
        if (mnem_eq(m, len, "tbz") || mnem_eq(m, len, "tbnz"))
            return InsnCategory::BRANCH;
        break;
    case 'p':
        if (mnem_eq(m, len, "paciasp") || mnem_eq(m, len, "pacibsp") ||
            mnem_eq(m, len, "pacia") || mnem_eq(m, len, "pacib") ||
            mnem_eq(m, len, "pacda") || mnem_eq(m, len, "pacdb"))
            return InsnCategory::BRANCH;  // PAC 签名指令，不影响数据流
        if (mnem_eq(m, len, "prfm") || mnem_eq(m, len, "prfum"))
            return InsnCategory::BRANCH;  // 预取，不影响数据流
        break;
    }
    return InsnCategory::OTHER;
}

// ============================================================
// 行类型检测
// ============================================================

bool TraceParser::is_instruction_line(const char* buf, int len) {
    return len > 0 && buf[0] == '[';
}

// ============================================================
// 操作数解析
// ============================================================

// 提取一个 token（字母数字），返回长度
static int extract_token(const char* s, int max_len, char* out, int out_size) {
    int i = 0;
    while (i < max_len && i < out_size - 1) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            out[i++] = c;
        else
            break;
    }
    out[i] = '\0';
    return i;
}

void TraceParser::parse_operands(const char* mnemonic, int mnem_len,
                                  const char* ops, int ops_len, TraceLine& out) {
    if (ops_len <= 0) return;

    bool is_store = (out.category == InsnCategory::STORE);
    bool is_compare = (out.category == InsnCategory::COMPARE);
    bool is_branch = (out.category == InsnCategory::BRANCH);
    bool is_ldp = false;
    if (mnem_len == 3 && memcmp(mnemonic, "ldp", 3) == 0) is_ldp = true;
    if (mnem_len == 5 && memcmp(mnemonic, "ldpsw", 5) == 0) is_ldp = true;
    bool is_stp = (mnem_len == 3 && memcmp(mnemonic, "stp", 3) == 0);

    // 分割操作数（逗号分隔，方括号内的逗号不分割）
    struct Operand {
        const char* start;
        int len;
        bool is_mem;    // 包含 [
    };
    Operand operands[8];
    int num_ops = 0;
    int bracket = 0;
    int seg_start = 0;

    for (int i = 0; i <= ops_len && num_ops < 8; i++) {
        char c = (i < ops_len) ? ops[i] : '\0';
        if (c == '[') bracket++;
        if (c == ']') bracket--;
        if ((c == ',' && bracket == 0) || c == '\0') {
            if (i > seg_start) {
                // trim leading spaces
                int s = seg_start;
                while (s < i && (ops[s] == ' ' || ops[s] == '\t')) s++;
                int e = i;
                while (e > s && (ops[e-1] == ' ' || ops[e-1] == '\t')) e--;
                if (e > s) {
                    operands[num_ops].start = ops + s;
                    operands[num_ops].len = e - s;
                    operands[num_ops].is_mem = false;
                    for (int j = s; j < e; j++) {
                        if (ops[j] == '[') { operands[num_ops].is_mem = true; break; }
                    }
                    num_ops++;
                }
            }
            seg_start = i + 1;
        }
    }

    if (num_ops == 0) return;

    // 分支：所有操作数都是源
    if (is_branch) {
        for (int i = 0; i < num_ops; i++) {
            char tok[8];
            int tlen = extract_token(operands[i].start, operands[i].len, tok, sizeof(tok));
            RegId rid = parse_reg_name(tok, tlen);
            if (rid != REG_INVALID && out.num_src < 8) {
                out.src_regs[out.num_src++] = rid;
            }
        }
        return;
    }

    // 比较：所有操作数都是源
    if (is_compare) {
        for (int i = 0; i < num_ops; i++) {
            if (operands[i].start[0] == '#') continue; // 立即数
            char tok[8];
            int tlen = extract_token(operands[i].start, operands[i].len, tok, sizeof(tok));
            RegId rid = parse_reg_name(tok, tlen);
            if (rid != REG_INVALID && out.num_src < 8) {
                out.src_regs[out.num_src++] = rid;
            }
        }
        return;
    }

    // 存储：寄存器操作数都是源，内存操作数中的基址/索引也是源
    if (is_store) {
        for (int i = 0; i < num_ops; i++) {
            if (operands[i].is_mem) {
                // 解析 [base, index, #off] 中的寄存器
                const char* p = operands[i].start;
                int plen = operands[i].len;
                for (int j = 0; j < plen; j++) {
                    if (p[j] == '[' || p[j] == ',' || p[j] == ' ') {
                        int k = j + 1;
                        while (k < plen && (p[k] == ' ')) k++;
                        if (k < plen && p[k] != '#' && p[k] != ']') {
                            char tok[8];
                            int tlen = extract_token(p + k, plen - k, tok, sizeof(tok));
                            RegId rid = parse_reg_name(tok, tlen);
                            if (rid != REG_INVALID && out.num_src < 8) {
                                out.src_regs[out.num_src++] = rid;
                            }
                        }
                    }
                }
            } else {
                char tok[8];
                int tlen = extract_token(operands[i].start, operands[i].len, tok, sizeof(tok));
                RegId rid = parse_reg_name(tok, tlen);
                if (rid != REG_INVALID && out.num_src < 8) {
                    out.src_regs[out.num_src++] = rid;
                }
            }
        }
        return;
    }

    // 通用：第一个（或前两个 for LDP/STP）是目标，其余是源
    for (int i = 0; i < num_ops; i++) {
        if (operands[i].is_mem) {
            // 内存操作数中的寄存器是源（基址/索引）
            const char* p = operands[i].start;
            int plen = operands[i].len;
            for (int j = 0; j < plen; j++) {
                if (p[j] == '[' || p[j] == ',' || p[j] == ' ') {
                    int k = j + 1;
                    while (k < plen && p[k] == ' ') k++;
                    if (k < plen && p[k] != '#' && p[k] != ']') {
                        char tok[8];
                        int tlen = extract_token(p + k, plen - k, tok, sizeof(tok));
                        RegId rid = parse_reg_name(tok, tlen);
                        if (rid != REG_INVALID && out.num_src < 8) {
                            out.src_regs[out.num_src++] = rid;
                        }
                    }
                }
            }
            continue;
        }

        // 跳过立即数和移位修饰符
        if (operands[i].start[0] == '#') continue;
        char tok[8];
        int tlen = extract_token(operands[i].start, operands[i].len, tok, sizeof(tok));
        // 移位修饰符
        if (memcmp(tok, "lsl", 3) == 0 || memcmp(tok, "lsr", 3) == 0 ||
            memcmp(tok, "asr", 3) == 0 || memcmp(tok, "ror", 3) == 0 ||
            memcmp(tok, "sxtb", 4) == 0 || memcmp(tok, "sxth", 4) == 0 ||
            memcmp(tok, "sxtw", 4) == 0 || memcmp(tok, "sxtx", 4) == 0 ||
            memcmp(tok, "uxtb", 4) == 0 || memcmp(tok, "uxth", 4) == 0 ||
            memcmp(tok, "uxtw", 4) == 0 || memcmp(tok, "uxtx", 4) == 0)
            continue;

        RegId rid = parse_reg_name(tok, tlen);
        if (rid == REG_INVALID) continue;

        if (i == 0) {
            if (out.num_dst < 4) out.dst_regs[out.num_dst++] = rid;
        } else if ((is_ldp || is_stp) && i == 1) {
            if (out.num_dst < 4) out.dst_regs[out.num_dst++] = rid;
        } else {
            if (out.num_src < 8) out.src_regs[out.num_src++] = rid;
        }
    }
}

// ============================================================
// 单行解析
// ============================================================

bool TraceParser::parse_line(const char* buf, int len, int line_number, long offset, TraceLine& out) {
    if (!is_instruction_line(buf, len)) return false;

    out.line_number = line_number;
    out.file_offset = offset;
    out.line_len = len;

    // 跳过 [module]
    int i = 1;
    while (i < len && buf[i] != ']') i++;
    if (i >= len) return false;
    i++; // skip ']'
    while (i < len && buf[i] == ' ') i++;

    // 解析 0xabs!0xrel
    if (i + 2 >= len || buf[i] != '0' || buf[i+1] != 'x') return false;
    i += 2;
    int hex_start = i;
    while (i < len && buf[i] != '!') i++;
    if (i >= len) return false;
    // abs_addr 不需要存储
    i++; // skip '!'
    if (i + 2 >= len || buf[i] != '0' || buf[i+1] != 'x') return false;
    i += 2;
    hex_start = i;
    while (i < len && buf[i] != ' ') i++;
    out.rel_addr = parse_hex_safe(buf + hex_start, i - hex_start);
    while (i < len && buf[i] == ' ') i++;

    // 解析 mnemonic
    int mnem_start = i;
    while (i < len && buf[i] != ' ' && buf[i] != '\t') i++;
    int mnem_len = i - mnem_start;
    if (mnem_len <= 0) return false;

    out.category = classify_mnemonic(buf + mnem_start, mnem_len);

    // 检测隐式写 NZCV 的指令（adds, subs, ands, bics, adcs, sbcs, negs, ngcs, cmp, cmn, tst, ccmp, ccmn）
    if (out.category == InsnCategory::COMPARE) {
        out.sets_flags = true;
    } else if (mnem_len >= 4) {
        const char* m = buf + mnem_start;
        if (m[mnem_len - 1] == 's') {
            // adds, subs, ands, bics, adcs, sbcs, negs, ngcs
            if (mnem_eq(m, mnem_len, "adds") || mnem_eq(m, mnem_len, "subs") ||
                mnem_eq(m, mnem_len, "ands") || mnem_eq(m, mnem_len, "bics") ||
                mnem_eq(m, mnem_len, "adcs") || mnem_eq(m, mnem_len, "sbcs") ||
                mnem_eq(m, mnem_len, "negs") || mnem_eq(m, mnem_len, "ngcs"))
                out.sets_flags = true;
        }
    }

    while (i < len && buf[i] == ' ') i++;

    // 剩余部分: operands ; reg_info 或 operands reg_info（无分号时）
    // 找分号位置
    int semi_pos = -1;
    for (int j = i; j < len - 1; j++) {
        if (buf[j] == ';' && buf[j+1] == ' ') {
            semi_pos = j;
            break;
        }
    }

    const char* ops_start;
    int ops_len;
    const char* info_start = nullptr;
    int info_len = 0;

    if (semi_pos >= 0) {
        ops_start = buf + i;
        ops_len = semi_pos - i;
        // trim trailing space from operands
        while (ops_len > 0 && ops_start[ops_len - 1] == ' ') ops_len--;
        info_start = buf + semi_pos + 2;
        info_len = len - semi_pos - 2;
    } else {
        // 没有 ';'，可能有 mem_w= 等直接跟在 operands 后面
        // 查找第一个 "寄存器名=0x" 模式
        int split = -1;
        for (int j = i; j < len - 3; j++) {
            if (buf[j] == '=' && buf[j+1] == '0' && buf[j+2] == 'x') {
                // 向前找寄存器名开始
                int k = j - 1;
                while (k > i && ((buf[k] >= 'a' && buf[k] <= 'z') ||
                                 (buf[k] >= '0' && buf[k] <= '9') || buf[k] == '_'))
                    k--;
                if (k < j - 1) {
                    split = k + 1;
                    break;
                }
            }
        }
        if (split >= 0) {
            ops_start = buf + i;
            ops_len = split - i;
            while (ops_len > 0 && ops_start[ops_len - 1] == ' ') ops_len--;
            info_start = buf + split;
            info_len = len - split;
        } else {
            ops_start = buf + i;
            ops_len = len - i;
            while (ops_len > 0 && ops_start[ops_len - 1] == ' ') ops_len--;
        }
    }

    // 解析 operands
    parse_operands(buf + mnem_start, mnem_len, ops_start, ops_len, out);

    // 解析 reg_info 中的 mem_r= 和 mem_w=
    if (info_start && info_len > 0) {
        for (int j = 0; j < info_len - 7; j++) {
            if (memcmp(info_start + j, "mem_r=0x", 8) == 0) {
                j += 8;
                int hs = j;
                while (j < info_len && ((info_start[j] >= '0' && info_start[j] <= '9') ||
                       (info_start[j] >= 'a' && info_start[j] <= 'f') ||
                       (info_start[j] >= 'A' && info_start[j] <= 'F'))) j++;
                out.has_mem_read = true;
                out.mem_read_addr = parse_hex_safe(info_start + hs, j - hs);
            } else if (memcmp(info_start + j, "mem_w=0x", 8) == 0) {
                j += 8;
                int hs = j;
                while (j < info_len && ((info_start[j] >= '0' && info_start[j] <= '9') ||
                       (info_start[j] >= 'a' && info_start[j] <= 'f') ||
                       (info_start[j] >= 'A' && info_start[j] <= 'F'))) j++;
                out.has_mem_write = true;
                out.mem_write_addr = parse_hex_safe(info_start + hs, j - hs);
            }
        }
    }

    // STP 双写：推断第二个写地址
    if (out.has_mem_write && out.category == InsnCategory::STORE &&
        mnem_len == 3 && memcmp(buf + mnem_start, "stp", 3) == 0) {
        // 检查第一个操作数是 x-reg(8字节) 还是 w-reg(4字节)
        // 由于 w→x 已归一化，通过原始操作数文本判断
        int reg_size = 8;  // 默认 64-bit
        if (ops_len > 0 && (ops_start[0] == 'w' || ops_start[0] == 'W')) {
            reg_size = 4;
        }
        out.has_mem_write2 = true;
        out.mem_write_addr2 = out.mem_write_addr + reg_size;
    }

    // LDP 双读：推断第二个读地址
    if (out.has_mem_read && out.category == InsnCategory::LOAD) {
        bool is_ldp_insn = (mnem_len == 3 && memcmp(buf + mnem_start, "ldp", 3) == 0) ||
                           (mnem_len == 5 && memcmp(buf + mnem_start, "ldpsw", 5) == 0) ||
                           (mnem_len == 4 && memcmp(buf + mnem_start, "ldxp", 4) == 0) ||
                           (mnem_len == 5 && memcmp(buf + mnem_start, "ldaxp", 5) == 0) ||
                           (mnem_len == 4 && memcmp(buf + mnem_start, "ldnp", 4) == 0);
        if (is_ldp_insn) {
            int reg_size = 8;
            if (ops_len > 0 && (ops_start[0] == 'w' || ops_start[0] == 'W')) {
                reg_size = 4;
            }
            out.has_mem_read2 = true;
            out.mem_read_addr2 = out.mem_read_addr + reg_size;
        }
    }

    return true;
}

// ============================================================
// 文件加载
// ============================================================

bool TraceParser::load(const std::string& filepath) {
    return load_range(filepath, INT32_MAX);
}

bool TraceParser::load_range_by_offset(const std::string& filepath, long max_offset) {
    filepath_ = filepath;
    lines_.clear();

    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open file: %s\n", filepath.c_str());
        return false;
    }

    lines_.reserve(1024 * 1024);

    static const int BUF_SIZE = 4096;
    char buf[BUF_SIZE];
    int line_number = 0;
    long cur_offset = 0;

    while (cur_offset <= max_offset) {
        long line_start = cur_offset;
        if (!fgets(buf, BUF_SIZE, fp)) break;

        line_number++;
        int len = (int)strlen(buf);
        cur_offset += len;
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) len--;

        if (len == 0) continue;

        if (is_instruction_line(buf, len)) {
            TraceLine tl = {};
            if (parse_line(buf, len, line_number, line_start, tl)) {
                lines_.push_back(tl);
            }
        }
    }

    fclose(fp);
    fprintf(stderr, "Loaded %zu instruction lines from %d file lines (up to offset %ld).\n",
            lines_.size(), line_number, max_offset);
    return true;
}

bool TraceParser::load_range(const std::string& filepath, int max_line) {
    filepath_ = filepath;
    lines_.clear();

    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open file: %s\n", filepath.c_str());
        return false;
    }

    // 预分配（粗估行数）
    lines_.reserve(1024 * 1024);

    static const int BUF_SIZE = 4096;
    char buf[BUF_SIZE];
    int line_number = 0;
    long cur_offset = 0;

    while (line_number < max_line) {
        long line_start = cur_offset;
        if (!fgets(buf, BUF_SIZE, fp)) break;

        line_number++;
        int len = (int)strlen(buf);
        cur_offset += len;  // 手动跟踪文件偏移，避免 ftell 开销
        // 去掉换行符
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) len--;

        if (len == 0) continue;

        if (is_instruction_line(buf, len)) {
            TraceLine tl = {};
            if (parse_line(buf, len, line_number, line_start, tl)) {
                lines_.push_back(tl);
            }
            continue;
        }
        // call func / args / ret / hexdump → skip
    }

    fclose(fp);
    fprintf(stderr, "Loaded %zu instruction lines from %d file lines.\n", lines_.size(), line_number);
    return true;
}

// ============================================================
// 查找
// ============================================================

int TraceParser::find_by_rel_addr(uint64_t rel_addr) const {
    for (size_t i = 0; i < lines_.size(); i++) {
        if (lines_[i].rel_addr == rel_addr) return (int)i;
    }
    return -1;
}

int TraceParser::find_by_offset(long byte_offset) const {
    // 二分查找（lines_ 按 file_offset 递增）
    int lo = 0, hi = (int)lines_.size() - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (lines_[mid].file_offset < byte_offset)
            lo = mid + 1;
        else if (lines_[mid].file_offset > byte_offset)
            hi = mid - 1;
        else
            return mid;
    }
    // 返回最接近的（>= byte_offset）
    return (lo < (int)lines_.size()) ? lo : -1;
}

int TraceParser::find_by_line(int line_number) const {
    // 二分查找（lines_ 按 line_number 递增）
    int lo = 0, hi = (int)lines_.size() - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (lines_[mid].line_number < line_number)
            lo = mid + 1;
        else if (lines_[mid].line_number > line_number)
            hi = mid - 1;
        else
            return mid;
    }
    // 返回最接近的（>=line_number）
    return (lo < (int)lines_.size()) ? lo : -1;
}

// ============================================================
// 回读原始行
// ============================================================

std::string TraceParser::read_raw_line(const TraceLine& tl) const {
    if (tl.file_offset < 0 || tl.line_len <= 0) return "";
    FILE* fp = fopen(filepath_.c_str(), "r");
    if (!fp) return "";
    fseek(fp, tl.file_offset, SEEK_SET);
    std::string result(tl.line_len, '\0');
    size_t n = fread(&result[0], 1, tl.line_len, fp);
    result.resize(n);
    fclose(fp);
    return result;
}

