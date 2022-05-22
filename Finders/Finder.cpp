//find bl instructions

#include "Finder.h"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <fstream>

using namespace std;
using namespace iblessing;

#define UnicornStackTopAddr      0x300000000

void output(cs_insn *insn) {
    cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, insn->op_str);
}

void output_found(cs_insn *insn) {
    cout << termcolor::green;
    cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, insn->op_str);

    cout << termcolor::reset;
}

void output_warning(uint64_t addr) {
    cout << termcolor::yellow << "[-] Warn: Failed to disassemble from";
    cout << StringUtils::format(" 0x%llx", addr);
    cout << termcolor::reset << endl;
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
            printf("%s:\n", sym->name.c_str());
            fprintf(file, "%s\n", sym->name.c_str());
        }


        if (strcmp(insn->mnemonic, "bl") == 0 ||
            strncmp(insn->mnemonic, "bl.", 2) == 0
        ) {
            output_found(insn);
        } else {
            output(insn);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}

void Finder::find_loops(const string &path) {
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
            printf("%s:\n", sym->name.c_str());
            fprintf(file, "%s\n", sym->name.c_str());
        }


        if (strcmp(insn->mnemonic, "b") == 0) {
            output_found(insn);
        } else {
            output(insn);
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

        Symbol *sym = symtab->getSymbolByAddress(addr);
        if (sym && sym->name.size() > 0) {
            printf("%s:\n", sym->name.c_str());
            fprintf(file, "%s\n", sym->name.c_str());
        }


        if (strcmp(insn->mnemonic, "b") == 0) {
            output_found(insn);
        } else {
            output(insn);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}

void Finder::find_conditionals(const string &path) {
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
            printf("%s:\n", sym->name.c_str());
            fprintf(file, "%s\n", sym->name.c_str());
        }


        if (
            strncmp(insn->mnemonic, "b.", 2) == 0 ||
            strcmp(insn->mnemonic, "cbz") == 0 ||
            strcmp(insn->mnemonic, "cbnz") == 0 ||
            strcmp(insn->mnemonic, "tbz") == 0 ||
            strcmp(insn->mnemonic, "tbnz") == 0
        ) {
            output_found(insn);
        } else {
            output(insn);
        }

        last_mnemonic = insn->mnemonic;
        addr += direction;
    }
}
