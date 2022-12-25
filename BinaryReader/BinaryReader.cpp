//
// Created by nafanya on 8/2/22.
//

#include "BinaryReader.h"
#include "../swift/include/swift/Demangling/Demangle.h"
#include <string>
#include "thread"

#define DEBUG 1

void logDebug(const std::string&);
void readSector(
        std::shared_ptr<iblessing::VirtualMemoryV2> &,
        uc_engine* &,
        csh &,
        std::shared_ptr<iblessing::SymbolTable> &,
        std::vector<cs_insn *> &,
        std::map<uint64_t, iblessing::Symbol *> &,
        uint64_t start_addr,
        uint64_t end_addr
);
BinaryReader::BinaryReader(const std::string& path) {
    using namespace iblessing;

    // prepare memory objects
    macho = MachO::createFromFile(path);
    logDebug("macho created");
    assert(macho->loadSync() == IB_SUCCESS);
    logDebug("macho loaded");

    ib_section_64 *textSect = macho->context->fileMemory->textSect;
    assert(textSect != nullptr);
    logDebug("text section loaded");

    memory = Memory::createFromMachO(macho);
    assert(memory->loadSync() == IB_SUCCESS);
    logDebug("memory created");

    // setup engine
    uc_engine *uc = memory->virtualMemory->getEngine();
    uint64_t unicorn_sp_start = UnicornStackTopAddr;
    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
    // set FPEN on CPACR_EL1
    uint32_t fpen;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
    fpen |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);

    std::shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    this->symtab = macho->context->symtab;

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;

    std::vector<std::thread> threads;
    uint64_t thread_amount = std::thread::hardware_concurrency();
    threads.reserve(thread_amount);

    std::vector<uint64_t> steps;
    uint64_t step = textSect->size / (thread_amount - 1);
    for (int i = 0; i < thread_amount - 1; i ++) {
        steps.push_back(step);
    }
    steps.push_back(textSect->size - step * (thread_amount - 1));

    for (int i = 0; i < thread_amount; i ++) {
        threads.emplace_back(
                std::thread(
                    readSector,
                    std::ref(vm2),
                    std::ref(uc),
                    std::ref(handle),
                    std::ref(symtab),
                    std::ref(codes),
                    std::ref(symbols),
                    addr + i * steps.at(i),
                    addr + (i+1) * steps.at(i)
                )
        );
    }

    for (int i = 0; i < thread_amount; i ++) {
        threads.at(i).join();
    }
}

void readSector(
    std::shared_ptr<iblessing::VirtualMemoryV2> &memory,
    uc_engine* &uc,
    csh &handle,
    std::shared_ptr<iblessing::SymbolTable> &symtab,
    std::vector<cs_insn *> &codes_container,
    std::map<uint64_t, iblessing::Symbol *> &symbol_container,
    uint64_t start_addr,
    uint64_t end_addr
) {
    uint64_t addr = start_addr;
    while (addr < end_addr) {
        std::cout << addr << std::endl;
        bool success;
        uint32_t code = memory->read32(addr, &success);
        if (!success) {
            addr += 4;
            continue;
        }

        cs_insn *insn = nullptr;
        // disassembly
        size_t count = cs_disasm(handle, (uint8_t *)&code, 4, addr, 0, &insn);
        if (count != 1) {
            addr += 4;
            continue;
        }

        uc_emu_start(uc, addr, addr + 4, 0, 1);
        uc_emu_stop(uc);

        iblessing::Symbol *sym = symtab->getSymbolByAddress(addr);

        if (sym && !sym->name.empty()) {
            symbol_container.insert(std::make_pair(addr, sym));
        }
        codes_container.push_back(insn);
        addr += 4;
    }
}

std::vector<cs_insn *> &BinaryReader::getCodes() {
    return this->codes;
}

std::map<uint64_t, iblessing::Symbol *> &BinaryReader::getSymbols() {
    return this->symbols;
}

std::map<uint64_t, std::string> &BinaryReader::getDemangledSymbols() {
    using namespace iblessing;
    using namespace swift::Demangle;
    auto* result = new std::map<uint64_t, std::string>();
    for (auto elem : this->symbols) {
        Symbol* sym = elem.second;
        std::string demangledSymbol = demangleSymbolAsString(
                sym->name.c_str(),
                strlen(sym->name.c_str()),
                DemangleOptions()
        );
        result->insert(std::make_pair(elem.first, demangledSymbol));
    }
    return *result;
}

std::shared_ptr<iblessing::SymbolTable> & BinaryReader::getSymtab() {
    return this->symtab;
}

void logDebug(const std::string & message) {
    if (DEBUG == 1) {
        std::cout << message << std::endl;
    }
}
