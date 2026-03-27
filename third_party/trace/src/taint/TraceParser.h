#ifndef TAINT_TRACEPARSER_H
#define TAINT_TRACEPARSER_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>

// 寄存器 ID 编码，避免存储字符串
enum RegId : uint8_t {
    REG_X0 = 0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7,
    REG_X8, REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
    REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
    REG_X24, REG_X25, REG_X26, REG_X27, REG_X28,
    REG_FP,     // x29
    REG_LR,     // x30
    REG_SP,
    REG_XZR,
    REG_NZCV,
    // SIMD（用于检测但不参与污点传播的核心逻辑）
    REG_Q0, REG_Q1, REG_Q2, REG_Q3, REG_Q4, REG_Q5, REG_Q6, REG_Q7,
    REG_Q8, REG_Q9, REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
    REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
    REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31,
    REG_D0, REG_D1, REG_D2, REG_D3, REG_D4, REG_D5, REG_D6, REG_D7,
    REG_D8, REG_D9, REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
    REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
    REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_D31,
    REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
    REG_S8, REG_S9, REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
    REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
    REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31,
    REG_INVALID = 255
};

// 指令类别（预分类，避免在追踪时反复字符串比较）
enum class InsnCategory : uint8_t {
    DATA_MOVE,          // mov, mvn, neg
    IMM_LOAD,           // movz, movn, adr, adrp
    PARTIAL_MODIFY,     // movk
    ARITHMETIC,         // add, sub, mul, etc.
    LOGIC,              // and, orr, eor, etc.
    SHIFT_EXT,          // lsl, lsr, asr, ror, sxt*, uxt*
    BITFIELD,           // ubfm, sbfm, bfm, bfi, bfxil, extr
    LOAD,               // ldr, ldrb, ldrh, ldrsw, ldp, ldur, etc.
    STORE,              // str, strb, strh, stp, stur, etc.
    COMPARE,            // cmp, cmn, tst
    COND_SELECT,        // csel, csinc, csinv, csneg
    BRANCH,             // b, bl, blr, br, ret, cbz, cbnz
    OTHER
};

// 紧凑指令表示（~64 bytes），用于内存高效存储
struct TraceLine {
    int line_number = 0;
    InsnCategory category = InsnCategory::OTHER;

    uint8_t num_dst = 0;
    uint8_t num_src = 0;
    RegId dst_regs[4] = {REG_INVALID, REG_INVALID, REG_INVALID, REG_INVALID};
    RegId src_regs[8] = {REG_INVALID, REG_INVALID, REG_INVALID, REG_INVALID,
                         REG_INVALID, REG_INVALID, REG_INVALID, REG_INVALID};

    uint64_t mem_read_addr = 0;
    uint64_t mem_write_addr = 0;
    uint64_t mem_write_addr2 = 0;   // STP 第二个写地址
    uint64_t mem_read_addr2 = 0;   // LDP 第二个读地址
    uint64_t rel_addr = 0;
    bool has_mem_read = false;
    bool has_mem_write = false;
    bool has_mem_write2 = false;    // STP 双写
    bool has_mem_read2 = false;     // LDP 双读
    bool sets_flags = false;        // adds, subs, ands 等隐式写 NZCV

    // 文件偏移，用于输出时回读原始行
    long file_offset = 0;
    int line_len = 0;           // 指令行长度（不含换行）
};

class TraceParser {
public:
    // 加载整个文件，构建指令索引
    bool load(const std::string& filepath);

    // 流式加载：只加载 [0, max_line] 范围的指令（用于反向追踪节省内存）
    bool load_range(const std::string& filepath, int max_line);

    // 流式加载：只加载 [0, max_offset] 字节范围的指令（用于反向追踪，按字节偏移截止）
    bool load_range_by_offset(const std::string& filepath, long max_offset);

    const std::vector<TraceLine>& get_lines() const { return lines_; }
    size_t size() const { return lines_.size(); }
    const std::string& get_filepath() const { return filepath_; }

    int find_by_rel_addr(uint64_t rel_addr) const;
    int find_by_line(int line_number) const;
    int find_by_offset(long byte_offset) const;

    // 根据文件偏移读取原始行内容（用于输出）
    std::string read_raw_line(const TraceLine& tl) const;

    // 寄存器名转换
    static const char* reg_name(RegId id);
    static RegId parse_reg_name(const char* s, int len);

    // 归一化寄存器（w→x, fp→x29, lr→x30）
    static RegId normalize(RegId id);

private:
    std::vector<TraceLine> lines_;
    std::string filepath_;

    bool parse_line(const char* buf, int len, int line_number, long offset, TraceLine& out);
    void parse_operands(const char* mnemonic, int mnem_len,
                        const char* operands, int ops_len, TraceLine& out);
    static InsnCategory classify_mnemonic(const char* mnem, int len);
    static uint64_t parse_hex_safe(const char* s, int len);
    static bool is_instruction_line(const char* buf, int len);
};

#endif // TAINT_TRACEPARSER_H
