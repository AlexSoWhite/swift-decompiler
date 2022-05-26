//find bl instructions

#include "Finder.h"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <fstream>
#include <sstream>
#include "../swift/include/swift/Demangling/Demangle.h"

using namespace std;
using namespace iblessing;
using namespace swift;

#define UnicornStackTopAddr      0x300000000

void output(cs_insn *insn, const shared_ptr<SymbolTable> & symtab) {
    Symbol *sym = symtab->getSymbolByAddress(insn->address);
    string demangled;
    if (sym && !sym->name.empty()) {
        demangled = Demangle::demangleSymbolAsString(
                sym->name.c_str(),
                strlen(sym->name.c_str()),
                Demangle::DemangleOptions()
        );
    }
    if (strcmp(insn->mnemonic, "bl") == 0) {
        cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, demangled.c_str());
    } else {
        if (demangled != "") {
            cout << demangled << endl;
        }
        cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, insn->op_str);
    }
}

void output_found(cs_insn *insn, const shared_ptr<SymbolTable> & symtab) {
    cout << termcolor::green;
    output(insn, symtab);
    cout << termcolor::reset;
}

void output_start(cs_insn *insn, const shared_ptr<SymbolTable> & symtab) {
    cout << termcolor::cyan;
    output(insn, symtab);
    cout << termcolor::reset;
}

void output_warning(uint64_t addr) {
    cout << termcolor::yellow << "[-] Warn: Failed to disassemble from";
    cout << StringUtils::format(" 0x%llx", addr);
    cout << termcolor::reset << endl;
}

uint64_t convert_opstr_to_address(char op_str[160]) {
    stringstream ss;
    ss << std::hex << op_str;
    uint64_t x;
    ss.ignore(1);
    ss >> x;
    return x;
}

bool extract_const_from_opstr(char op_str[160], uint64_t value) {
    stringstream ss;
    vector<int> indexes;
    for (int i = 0; i < 160; i++) {
        if (op_str[i] == '#') {
            indexes.push_back(i);
        }
    }
    if (indexes.empty()) {
        return false;
    }
    for (auto index : indexes) {
        uint64_t constant;
        ss << std::hex << op_str;
        ss.ignore(index+1);
        ss >> constant;
        ss.clear();
        if (constant == value) {
            return true;
        }
    }

    return false;
}

void Finder::find_functions(const string & path) {
    int straight = 4;
    int reversed = -4;
    shared_ptr<MachO> macho = MachO::createFromFile(path);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);

    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    uint64_t last_addr;
    int direction = straight;
    string last_mnemonic;
    // log file
    FILE * file = fopen("log", "w");

    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            output_warning(addr);
            last_mnemonic = "";
            addr += direction;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            output_warning(addr);
            addr += direction;
            last_mnemonic = "";
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

        Symbol *sym = symtab->getSymbolByAddress(addr);

        if (sym && sym->name.size() > 0) {
            string demangled = Demangle::demangleSymbolAsString(sym->name.c_str(), strlen(sym->name.c_str()), Demangle::DemangleOptions());
            cout << demangled << endl;
            fprintf(file, "%s\n", demangled.c_str());
        }

        if (strcmp(insn->mnemonic, "bl") == 0 ||
            strncmp(insn->mnemonic, "bl.", 2) == 0
        ) {
            output_found(insn, symtab);
        } else {
            output(insn, symtab);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}

void Finder::find_loops(const string &path) {
    int straight = 4;
    int reversed = -4;
    vector<uint64_t> start_addresses;
    vector<uint64_t> end_addresses;
    vector<cs_insn *> codes;
    shared_ptr<MachO> macho = MachO::createFromFile(path);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%lx\n", textSect->addr);

    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    uint64_t last_addr;
    int direction = straight;
    string last_mnemonic;
    // log file
    FILE * file = fopen("log", "w");

    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            output_warning(addr);
            last_mnemonic = "";
            addr += direction;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            output_warning(addr);
            addr += direction;
            last_mnemonic = "";
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

//        Symbol *sym = symtab->getSymbolByAddress(addr);
//        if (sym && sym->name.size() > 0) {
//            printf("%s:\n", sym->name.c_str());
//            fprintf(file, "%s\n", sym->name.c_str());
//        }

        codes.push_back(insn);
        if (strcmp(insn->mnemonic, "b") == 0) {
            uint64_t _address = convert_opstr_to_address(insn->op_str);
            if (_address < addr) {
                start_addresses.push_back(_address);
                end_addresses.push_back(addr);
            }
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }

    for (auto code : codes) {
        if (find(start_addresses.begin(), start_addresses.end(), code->address) != start_addresses.end()) {
            output_start(code, symtab);
        } else if (find(end_addresses.begin(), end_addresses.end(), code->address) != end_addresses.end()) {
            output_found(code, symtab);
        } else {
            output(code, symtab);
        }
    }
}

void Finder::find_constants(const string &path, uint64_t value) {
    int straight = 4;
    int reversed = -4;
    shared_ptr<MachO> macho = MachO::createFromFile(path);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);

    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    uint64_t last_addr;
    int direction = straight;
    string last_mnemonic;
    // log file
    FILE * file = fopen("log", "w");

    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            output_warning(addr);
            last_mnemonic = "";
            addr += direction;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            output_warning(addr);
            addr += direction;
            last_mnemonic = "";
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

        if (extract_const_from_opstr(insn->op_str, value)) {
            output_found(insn, symtab);
        } else {
            output(insn, symtab);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}

void Finder::find_variables(const string &path) {
    int straight = 4;
    int reversed = -4;
    shared_ptr<MachO> macho = MachO::createFromFile(path);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);

    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    uint64_t last_addr;
    int direction = straight;
    string last_mnemonic;
    // log file
    FILE * file = fopen("log", "w");

    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            output_warning(addr);
            last_mnemonic = "";
            addr += direction;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            output_warning(addr);
            addr += direction;
            last_mnemonic = "";
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

        if (
            strcmp(insn->mnemonic, "mov") == 0 ||
            strcmp(insn->mnemonic, "str") == 0 ||
            strcmp(insn->mnemonic, "ldr") == 0
        ) {
            cout << insn->detail->arm64.operands->reg;
            output_found(insn, symtab);
        } else {
            output(insn, symtab);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}

void Finder::find_conditionals(const string &path) {
    const int straight = 4;
    const int reversed = -4;
    vector<uint64_t> branch_addresses;
    vector<uint64_t> cond_addresses;
    vector<cs_insn*> codes;
    shared_ptr<MachO> macho = MachO::createFromFile(path);
    assert(macho->loadSync() == IB_SUCCESS);
    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    printf("[+] find __TEXT,__text at 0x%llx\n", textSect->addr);

    shared_ptr<Memory> memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    shared_ptr<SymbolTable> symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;
    uint64_t last_addr;
    int direction = straight;
    string last_mnemonic;
    // log file
    FILE * file = fopen("log", "w");

    while (addr < end) {
        bool success;
        uint32_t code = vm2->read32(addr, &success);
        if (!success) {
            output_warning(addr);
            last_mnemonic = "";
            addr += direction;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            output_warning(addr);
            addr += direction;
            last_mnemonic = "";
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

        switch (direction) {
            case straight:
                codes.push_back(insn);
                if (
                    strncmp(insn->mnemonic, "b.", 2) == 0 ||
                    strcmp(insn->mnemonic, "cbz") == 0 ||
                    strcmp(insn->mnemonic, "cbnz") == 0 ||
                    strcmp(insn->mnemonic, "tbz") == 0 ||
                    strcmp(insn->mnemonic, "tbnz") == 0
                ) {
                    direction = reversed;
                    branch_addresses.push_back(addr);
                    last_addr = addr;
                }
                break;
            case reversed:
                if (
                    strcmp(insn->mnemonic, "cmp") == 0 ||
                    strcmp(insn->mnemonic, "cmn") == 0 ||
                    strcmp(insn->mnemonic, "ccmn") == 0 ||
                    strcmp(insn->mnemonic, "ccmp") == 0
                ) {
                    cond_addresses.push_back(addr);
                    addr = last_addr + 4;
                    direction = straight;
                }
                break;
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
    for (auto code : codes) {
        if (find(cond_addresses.begin(), cond_addresses.end(), code->address) != cond_addresses.end()) {
            output_start(code, symtab);
        } else if (find(branch_addresses.begin(), branch_addresses.end(), code->address) != branch_addresses.end()) {
            output_found(code, symtab);
        } else {
            output(code, symtab);
        }
    }
}
