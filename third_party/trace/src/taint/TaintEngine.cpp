#include "TaintEngine.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ============================================================
// 污点检查
// ============================================================

bool TaintEngine::any_src_tainted(const TraceLine& line) const {
    for (int i = 0; i < line.num_src; i++) {
        if (is_reg_tainted(line.src_regs[i])) return true;
    }
    if (line.has_mem_read && tainted_mem_.count(line.mem_read_addr)) return true;
    if (line.has_mem_read2 && tainted_mem_.count(line.mem_read_addr2)) return true;
    return false;
}

bool TaintEngine::any_dst_tainted(const TraceLine& line) const {
    for (int i = 0; i < line.num_dst; i++) {
        if (is_reg_tainted(line.dst_regs[i])) return true;
    }
    if (line.has_mem_write && tainted_mem_.count(line.mem_write_addr)) return true;
    if (line.has_mem_write2 && tainted_mem_.count(line.mem_write_addr2)) return true;
    return false;
}

// ============================================================
// 设置
// ============================================================

void TaintEngine::set_source(const TaintSource& source) {
    source_ = source;
    memset(reg_taint_, 0, sizeof(reg_taint_));
    tainted_reg_count_ = 0;
    tainted_mem_.clear();
    results_.clear();
    stop_reason_ = StopReason::END_OF_TRACE;

    if (source.is_mem) {
        tainted_mem_.insert(source.mem_addr);
    } else {
        taint_reg(source.reg);
    }
}

void TaintEngine::record(int index) {
    ResultEntry entry;
    entry.index = index;
    memcpy(entry.reg_snapshot, reg_taint_, sizeof(reg_taint_));
    entry.mem_snapshot = tainted_mem_;
    results_.push_back(std::move(entry));
}

int TaintEngine::count_tainted_regs() const {
    return tainted_reg_count_;
}

// ============================================================
// 正向传播
// ============================================================

void TaintEngine::propagate_forward(const TraceLine& line) {
    switch (line.category) {
        case InsnCategory::IMM_LOAD: {
            for (int i = 0; i < line.num_dst; i++) untaint_reg(line.dst_regs[i]);
            break;
        }
        case InsnCategory::PARTIAL_MODIFY: {
            // movk 保持目标已有污点
            break;
        }
        case InsnCategory::DATA_MOVE:
        case InsnCategory::ARITHMETIC:
        case InsnCategory::LOGIC:
        case InsnCategory::SHIFT_EXT:
        case InsnCategory::BITFIELD:
        case InsnCategory::COND_SELECT: {
            bool src_t = any_src_tainted(line);
            for (int i = 0; i < line.num_dst; i++) {
                if (src_t) taint_reg(line.dst_regs[i]);
                else untaint_reg(line.dst_regs[i]);
            }
            // adds, subs, ands 等隐式写 NZCV
            if (line.sets_flags) {
                if (src_t) taint_reg(REG_NZCV);
                else untaint_reg(REG_NZCV);
            }
            break;
        }
        case InsnCategory::LOAD: {
            // LDP 双读：分别检查两个内存地址
            if (line.has_mem_read2 && line.num_dst >= 2) {
                bool mem_t1 = line.has_mem_read && tainted_mem_.count(line.mem_read_addr);
                bool mem_t2 = tainted_mem_.count(line.mem_read_addr2);
                if (mem_t1) taint_reg(line.dst_regs[0]);
                else untaint_reg(line.dst_regs[0]);
                if (mem_t2) taint_reg(line.dst_regs[1]);
                else untaint_reg(line.dst_regs[1]);
            } else {
                bool mem_t = line.has_mem_read && tainted_mem_.count(line.mem_read_addr);
                for (int i = 0; i < line.num_dst; i++) {
                    if (mem_t) taint_reg(line.dst_regs[i]);
                    else untaint_reg(line.dst_regs[i]);
                }
            }
            break;
        }
        case InsnCategory::STORE: {
            if (line.has_mem_write) {
                // STP: 第一个 src 写到 mem_write_addr，第二个 src 写到 mem_write_addr2
                if (line.has_mem_write2 && line.num_src >= 2) {
                    // 第一个数据寄存器
                    if (is_reg_tainted(line.src_regs[0])) tainted_mem_.insert(line.mem_write_addr);
                    else tainted_mem_.erase(line.mem_write_addr);
                    // 第二个数据寄存器
                    if (is_reg_tainted(line.src_regs[1])) tainted_mem_.insert(line.mem_write_addr2);
                    else tainted_mem_.erase(line.mem_write_addr2);
                } else {
                    // 非 STP：只检查数据寄存器（src_regs[0]），不检查基址/索引寄存器
                    bool src_t = (line.num_src > 0 && is_reg_tainted(line.src_regs[0]));
                    if (src_t) tainted_mem_.insert(line.mem_write_addr);
                    else tainted_mem_.erase(line.mem_write_addr);
                }
            }
            break;
        }
        case InsnCategory::COMPARE: {
            bool src_t = any_src_tainted(line);
            if (src_t) taint_reg(REG_NZCV);
            else untaint_reg(REG_NZCV);
            break;
        }
        case InsnCategory::BRANCH:
            break;
        case InsnCategory::OTHER: {
            bool src_t = any_src_tainted(line);
            for (int i = 0; i < line.num_dst; i++) {
                if (src_t) taint_reg(line.dst_regs[i]);
                else untaint_reg(line.dst_regs[i]);
            }
            if (line.has_mem_write) {
                if (src_t) tainted_mem_.insert(line.mem_write_addr);
                else tainted_mem_.erase(line.mem_write_addr);
            }
            break;
        }
    }
}

// ============================================================
// 反向传播
// ============================================================

void TaintEngine::propagate_backward(const TraceLine& line) {
    switch (line.category) {
        case InsnCategory::IMM_LOAD: {
            for (int i = 0; i < line.num_dst; i++) {
                if (is_reg_tainted(line.dst_regs[i])) untaint_reg(line.dst_regs[i]);
            }
            break;
        }
        case InsnCategory::PARTIAL_MODIFY:
            break;
        case InsnCategory::DATA_MOVE:
        case InsnCategory::ARITHMETIC:
        case InsnCategory::LOGIC:
        case InsnCategory::SHIFT_EXT:
        case InsnCategory::BITFIELD:
        case InsnCategory::COND_SELECT: {
            bool dst_t = any_dst_tainted(line);
            // adds, subs, ands 等也隐式写了 NZCV，反向需要检查
            bool nzcv_t = line.sets_flags && is_reg_tainted(REG_NZCV);
            if (dst_t || nzcv_t) {
                for (int i = 0; i < line.num_dst; i++) untaint_reg(line.dst_regs[i]);
                if (nzcv_t) untaint_reg(REG_NZCV);
                for (int i = 0; i < line.num_src; i++) taint_reg(line.src_regs[i]);
            }
            break;
        }
        case InsnCategory::LOAD: {
            // LDP 双读反向传播
            if (line.has_mem_read2 && line.num_dst >= 2) {
                bool t0 = is_reg_tainted(line.dst_regs[0]);
                bool t1 = is_reg_tainted(line.dst_regs[1]);
                if (t0) {
                    untaint_reg(line.dst_regs[0]);
                    if (line.has_mem_read) tainted_mem_.insert(line.mem_read_addr);
                }
                if (t1) {
                    untaint_reg(line.dst_regs[1]);
                    tainted_mem_.insert(line.mem_read_addr2);
                }
            } else {
                bool dst_t = false;
                for (int i = 0; i < line.num_dst; i++) {
                    if (is_reg_tainted(line.dst_regs[i])) { dst_t = true; untaint_reg(line.dst_regs[i]); }
                }
                if (dst_t && line.has_mem_read) tainted_mem_.insert(line.mem_read_addr);
            }
            break;
        }
        case InsnCategory::STORE: {
            if (line.has_mem_write) {
                // STP 双写
                if (line.has_mem_write2 && line.num_src >= 2) {
                    if (tainted_mem_.count(line.mem_write_addr)) {
                        tainted_mem_.erase(line.mem_write_addr);
                        taint_reg(line.src_regs[0]);
                    }
                    if (tainted_mem_.count(line.mem_write_addr2)) {
                        tainted_mem_.erase(line.mem_write_addr2);
                        taint_reg(line.src_regs[1]);
                    }
                } else if (tainted_mem_.count(line.mem_write_addr)) {
                    tainted_mem_.erase(line.mem_write_addr);
                    if (line.num_src > 0) taint_reg(line.src_regs[0]);
                }
            }
            break;
        }
        case InsnCategory::COMPARE: {
            if (is_reg_tainted(REG_NZCV)) {
                untaint_reg(REG_NZCV);
                for (int i = 0; i < line.num_src; i++) taint_reg(line.src_regs[i]);
            }
            break;
        }
        case InsnCategory::BRANCH:
            break;
        case InsnCategory::OTHER: {
            bool dst_t = any_dst_tainted(line);
            if (dst_t) {
                for (int i = 0; i < line.num_dst; i++) untaint_reg(line.dst_regs[i]);
                for (int i = 0; i < line.num_src; i++) taint_reg(line.src_regs[i]);
                if (line.has_mem_read) tainted_mem_.insert(line.mem_read_addr);
            }
            break;
        }
    }
}

// ============================================================
// 主执行
// ============================================================

void TaintEngine::run(const std::vector<TraceLine>& lines, int start_index) {
    results_.clear();
    stop_reason_ = StopReason::END_OF_TRACE;

    if (mode_ == TrackMode::FORWARD) {
        // 起始行记录
        record(start_index);

        int lines_since_last_propagation = 0;

        for (int i = start_index + 1; i < (int)lines.size(); i++) {
            const auto& line = lines[i];

            // 检查源是否有污点（传播事件）
            bool involved = any_src_tainted(line);

            // 检查是否覆盖了已被污染的内存（消亡事件）
            if (!involved && line.has_mem_write && tainted_mem_.count(line.mem_write_addr))
                involved = true;
            if (!involved && line.has_mem_write2 && tainted_mem_.count(line.mem_write_addr2))
                involved = true;

            propagate_forward(line);

            if (involved) {
                record(i);
                lines_since_last_propagation = 0;
            } else {
                lines_since_last_propagation++;
                if (lines_since_last_propagation >= max_scan_distance_) {
                    stop_reason_ = StopReason::SCAN_LIMIT_REACHED;
                    break;
                }
            }

            if (count_tainted_regs() == 0 && tainted_mem_.empty()) {
                stop_reason_ = StopReason::ALL_TAINT_CLEARED;
                break;
            }
        }
    } else {
        // 起始行：执行反向传播
        propagate_backward(lines[start_index]);
        record(start_index);

        int lines_since_last_propagation = 0;

        for (int i = start_index - 1; i >= 0; i--) {
            const auto& line = lines[i];
            bool involved = any_dst_tainted(line);
            if (!involved && line.has_mem_write && tainted_mem_.count(line.mem_write_addr))
                involved = true;
            if (!involved && line.has_mem_write2 && tainted_mem_.count(line.mem_write_addr2))
                involved = true;
            if (!involved && line.sets_flags && is_reg_tainted(REG_NZCV))
                involved = true;

            if (involved) {
                propagate_backward(line);
                record(i);
                lines_since_last_propagation = 0;
            } else {
                lines_since_last_propagation++;
                if (lines_since_last_propagation >= max_scan_distance_) {
                    stop_reason_ = StopReason::SCAN_LIMIT_REACHED;
                    break;
                }
            }

            if (count_tainted_regs() == 0 && tainted_mem_.empty()) {
                stop_reason_ = StopReason::ALL_TAINT_CLEARED;
                break;
            }
        }

        std::reverse(results_.begin(), results_.end());
    }
}

// ============================================================
// 输出
// ============================================================

bool TaintEngine::write_result(const std::string& output_path, const TraceParser& parser) const {
    FILE* out = fopen(output_path.c_str(), "w");
    if (!out) {
        fprintf(stderr, "Error: cannot open output file: %s\n", output_path.c_str());
        return false;
    }

    // 打开源文件用于回读原始行
    FILE* src = fopen(parser.get_filepath().c_str(), "r");

    const auto& lines = parser.get_lines();

    fprintf(out, "=== Taint %s Tracking ===\n",
            mode_ == TrackMode::FORWARD ? "Forward" : "Backward");
    fprintf(out, "Source: ");
    if (source_.is_mem)
        fprintf(out, "mem:0x%lx", (unsigned long)source_.mem_addr);
    else
        fprintf(out, "%s", TraceParser::reg_name(source_.reg));
    fprintf(out, "\nTotal matched: %zu instructions\n", results_.size());

    // 停止原因
    switch (stop_reason_) {
        case StopReason::ALL_TAINT_CLEARED:
            fprintf(out, "Stop reason: all taint cleared\n");
            break;
        case StopReason::SCAN_LIMIT_REACHED:
            fprintf(out, "Stop reason: scan limit reached (%d lines without propagation)\n", max_scan_distance_);
            break;
        case StopReason::END_OF_TRACE:
            fprintf(out, "Stop reason: end of trace\n");
            break;
    }

    fprintf(out, "============================================================\n\n");

    char line_buf[4096];

    for (const auto& entry : results_) {
        const auto& tl = lines[entry.index];

        // 读取原始行
        if (src && tl.line_len > 0 && tl.line_len < (int)sizeof(line_buf)) {
            fseek(src, tl.file_offset, SEEK_SET);
            int n = (int)fread(line_buf, 1, tl.line_len, src);
            line_buf[n] = '\0';
            fprintf(out, "[%d] %s\n", tl.line_number, line_buf);
        } else {
            fprintf(out, "[%d] (line too long or read error)\n", tl.line_number);
        }

        // 污点快照
        fprintf(out, "      tainted: {");
        bool first = true;
        for (int i = 0; i < 256; i++) {
            if (entry.reg_snapshot[i]) {
                if (!first) fprintf(out, ", ");
                fprintf(out, "%s", TraceParser::reg_name((RegId)i));
                first = false;
            }
        }
        for (const auto& m : entry.mem_snapshot) {
            if (!first) fprintf(out, ", ");
            fprintf(out, "mem:0x%lx", (unsigned long)m);
            first = false;
        }
        fprintf(out, "}\n\n");
    }

    if (src) fclose(src);
    fclose(out);

    fprintf(stderr, "Result written to: %s (%zu instructions)\n", output_path.c_str(), results_.size());
    return true;
}
