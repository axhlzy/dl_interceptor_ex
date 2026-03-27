#include "TraceParser.h"
#include "TaintEngine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <file>       Input trace log file\n");
    fprintf(stderr, "  -o <file>       Output result log file\n");
    fprintf(stderr, "  -f <target>     Forward tracking (from source)\n");
    fprintf(stderr, "  -b <target>     Backward tracking (to target)\n");
    fprintf(stderr, "  -l <line>       Start line number in trace file\n");
    fprintf(stderr, "  -p <offset>     Start by byte offset in trace file\n");
    fprintf(stderr, "  -a <addr>       Start by relative address (hex, e.g. 0x1890)\n");
    fprintf(stderr, "  -h              Show this help\n\n");
    fprintf(stderr, "Target format:\n");
    fprintf(stderr, "  x0, w1, sp, ...         Register name\n");
    fprintf(stderr, "  mem:0x1000              Memory address\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s -i trace.log -o result.log -f x0 -l 100\n", prog);
    fprintf(stderr, "  %s -i trace.log -o result.log -b x0 -l 500\n", prog);
    fprintf(stderr, "  %s -i trace.log -o result.log -f mem:0x1000 -l 100\n", prog);
}

static TaintSource parse_target(const char* target) {
    TaintSource src;
    if (strncmp(target, "mem:", 4) == 0) {
        src.is_mem = true;
        const char* addr = target + 4;
        if (addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) addr += 2;
        src.mem_addr = strtoull(addr, nullptr, 16);
    } else {
        src.is_mem = false;
        src.reg = TraceParser::parse_reg_name(target, (int)strlen(target));
        if (src.reg == REG_INVALID) {
            fprintf(stderr, "Error: unknown register '%s'\n", target);
        }
    }
    return src;
}

int main(int argc, char* argv[]) {
    const char* input_file = nullptr;
    const char* output_file = nullptr;
    const char* target = nullptr;
    TrackMode mode = TrackMode::FORWARD;
    int start_line = -1;
    long start_offset = -1;
    uint64_t start_addr = 0;
    bool use_addr = false;
    bool use_offset = false;
    bool has_mode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            target = argv[++i];
            mode = TrackMode::FORWARD;
            has_mode = true;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            target = argv[++i];
            mode = TrackMode::BACKWARD;
            has_mode = true;
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            start_line = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            start_offset = atol(argv[++i]);
            use_offset = true;
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            const char* addr = argv[++i];
            if (addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) addr += 2;
            start_addr = strtoull(addr, nullptr, 16);
            use_addr = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!input_file || !output_file || !has_mode || !target) {
        fprintf(stderr, "Error: -i, -o, -f/-b, and -l/-a are all required\n");
        print_usage(argv[0]);
        return 1;
    }
    if (start_line < 0 && !use_addr && !use_offset) {
        fprintf(stderr, "Error: -l, -p, or -a is required\n");
        print_usage(argv[0]);
        return 1;
    }

    TaintSource source = parse_target(target);
    if (!source.is_mem && source.reg == REG_INVALID) return 1;

    // -p：将字节偏移转换为行号，然后复用 -l 的代码路径
    if (use_offset && start_line < 0) {
        FILE* fp = fopen(input_file, "rb");
        if (!fp) {
            fprintf(stderr, "Error: cannot open file: %s\n", input_file);
            return 1;
        }
        int line_num = 1;
        static const int SCAN_BUF = 262144;  // 256KB
        char* scan_buf = new char[SCAN_BUF];
        long scanned = 0;
        while (scanned < start_offset) {
            long remaining = start_offset - scanned;
            int to_read = (remaining < SCAN_BUF) ? (int)remaining : SCAN_BUF;
            int n = (int)fread(scan_buf, 1, to_read, fp);
            if (n <= 0) break;
            for (int j = 0; j < n; j++) {
                if (scan_buf[j] == '\n') line_num++;
            }
            scanned += n;
        }
        delete[] scan_buf;
        fclose(fp);
        start_line = line_num;
        fprintf(stderr, "Converted byte offset %ld -> line %d\n", start_offset, start_line);
    }

    auto t0 = std::chrono::steady_clock::now();

    // 加载 trace
    TraceParser parser;
    if (mode == TrackMode::BACKWARD && start_line > 0) {
        // 反向追踪只需要加载到目标行
        fprintf(stderr, "Loading trace (up to line %d)...\n", start_line);
        if (!parser.load_range(input_file, start_line)) return 1;
    } else {
        fprintf(stderr, "Loading trace...\n");
        if (!parser.load(input_file)) return 1;
    }

    if (parser.size() == 0) {
        fprintf(stderr, "Error: no instruction lines found\n");
        return 1;
    }

    auto t1 = std::chrono::steady_clock::now();
    double load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    fprintf(stderr, "Load time: %.1f ms\n", load_ms);

    // 定位起始索引
    const auto& lines = parser.get_lines();
    int start_index = -1;

    if (use_addr) {
        start_index = parser.find_by_rel_addr(start_addr);
        if (start_index < 0) {
            fprintf(stderr, "Error: relative address 0x%lx not found\n", (unsigned long)start_addr);
            return 1;
        }
        fprintf(stderr, "Found address 0x%lx at index %d (line %d)\n",
                (unsigned long)start_addr, start_index, lines[start_index].line_number);
    } else {
        start_index = parser.find_by_line(start_line);
        if (start_index < 0) {
            fprintf(stderr, "Error: line %d not found\n", start_line);
            return 1;
        }
    }

    // 追踪
    TaintEngine engine;
    engine.set_mode(mode);
    engine.set_source(source);

    fprintf(stderr, "Running %s tracking from index %d (line %d) target: %s\n",
            mode == TrackMode::FORWARD ? "forward" : "backward",
            start_index, lines[start_index].line_number, target);

    auto t2 = std::chrono::steady_clock::now();
    engine.run(lines, start_index);
    auto t3 = std::chrono::steady_clock::now();
    double track_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();
    fprintf(stderr, "Tracking time: %.1f ms\n", track_ms);

    // 输出
    engine.write_result(output_file, parser);

    auto t4 = std::chrono::steady_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(t4 - t0).count();
    fprintf(stderr, "Total time: %.1f ms\n", total_ms);

    return 0;
}
