//
// Created by nafanya on 11/24/22.
//
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <fstream>
#include <sstream>
#include "../swift/include/swift/Demangling/Demangle.h"
#include "../include/SwiftDecompiler.h"
#include <thread>
#include <iomanip>

using namespace iblessing;
using namespace std;
using namespace swift;

std::string last_path_segment(const char * path) {
    std::string lp(path);
    lp = lp.substr(lp.find_last_of('/')+1);
    return lp;
}

void normalize_spaces(std::string& s) {
    int idx = 0;
    while (idx < s.size()) {
        if (s[idx] == ' ') {
            s = s.substr(0, idx) + "\\" + s.substr(idx);
            idx++;
        }
        idx++;
    }
}

string demangle_symbol(Symbol * sym) {
    return Demangle::demangleSymbolAsString(
        sym->name.c_str(),
        strlen(sym->name.c_str()),
        Demangle::DemangleOptions()
    );
}

string demangle_string(const string& s) {
    return Demangle::demangleSymbolAsString(
            s.c_str(),
            s.size(),
            Demangle::DemangleOptions()
    );
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

vector<cs_insn *> Binary::search_for_symbol(const std::string & symbol, bool search_for_demangled) {
    vector<cs_insn *> result = vector<cs_insn *>();
    for (auto code : codes) {
        Symbol * sym = symtab->getSymbolByAddress(code->address);
        if (sym && !sym->name.empty()) {
            if (search_for_demangled) {
                string demangled = demangle_symbol(sym);
                if (demangled.find(symbol) != string::npos) {
                    result.push_back(code);
                }
            } else if (sym->name == symbol) {
                result.push_back(code);
            }
        }
    }
    return result;
}

vector<cs_insn *> Binary::search_for_function(const string & function_name) {
    return this->search_for_symbol(function_name, true);
}

vector<cs_insn *> Binary::search_for_function_usages(const string & function_name) {
    vector<cs_insn *> result = vector<cs_insn *>();
    for (auto code : codes) {
        if (strcmp(code->mnemonic, "bl") == 0 ||
            strncmp(code->mnemonic, "bl.", 2) == 0
        ) {
            Symbol * sym = symtab->getSymbolByAddress(code->address);
            if (sym->name == function_name) {
                result.push_back(code);
            }
        }
    }
    return result;
}

vector<vector<cs_insn *>> Binary::search_for_loops() {
    vector<cs_insn *> loop = vector<cs_insn *>();
    vector<vector<cs_insn *>> result = vector<vector<cs_insn *>>();
    for (auto code : codes) {
        if (strcmp(code->mnemonic, "b") == 0) {
            uint64_t _address = convert_opstr_to_address(code->op_str);
            if (_address < code->address) {
                for (uint64_t addr = _address; addr <= code->address; addr += 4) {
                    loop.push_back(codes.at(addr/4));
                }
                result.push_back(loop);
                loop.clear();
            }
        }
    }
    return result;
}

vector<cs_insn *> Binary::search_for_class(const string & name) {
    return this->search_for_symbol(name, true);
}

vector<cs_insn *> Binary::search_for_structure(const string & name) {
    return this->search_for_symbol(name, true);
}

vector<cs_insn *> Binary::search_for_constants(uint64_t value) {
    vector<cs_insn *> result = vector<cs_insn *>();
    for (auto code : codes) {
        if (extract_const_from_opstr(code->op_str, value)) {
            result.push_back(code);
        }
    }
    return result;
}

vector<string> Binary::get_strings(const std::string& path, const std::string& grep_str) {
    vector<string> result = vector<string>();
    std::stringstream ss;
    std::string _path = path;
    std::string _name = last_path_segment(path.c_str());
    normalize_spaces(_path);
    normalize_spaces(_name);
    std::string string_path = "strings_" + _name;
    ss << "strings " << _path << " | grep \"" << grep_str << "\" > " << string_path;
    system(ss.str().c_str());
    std::ifstream fin(string_path);
    while (!fin.eof()) {
        std::string s;
        getline(fin, s);
        result.push_back(s);
    }
    fin.close();
    return result;
}

vector<string> Binary::get_sym_strings() {
    vector<string> result = vector<string>();
    for (int i = 0; i < this->stringtab->stringDataSize;) {
        string s = this->stringtab->getStringAtIndex(i);
        if (s.empty()) {
            i += 1;
        } else {
            i += s.size();
            result.push_back(demangle_string(s));
        }
    }
    return result;
}

void output(std::ostream& out, cs_insn *insn, const shared_ptr<SymbolTable> & symtab) {
    Symbol *sym = symtab->getSymbolByAddress(insn->address);
    string demangled;
//    if (sym) {
//        cout << sym << endl;
//        int a = 0;
//    }
    if (sym && !sym->name.empty()) {
        demangled = Demangle::demangleSymbolAsString(
                sym->name.c_str(),
                strlen(sym->name.c_str()),
                Demangle::DemangleOptions()
        );
    }
    if (strcmp(insn->mnemonic, "bl") == 0) {
        out << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, demangled.c_str());
    } else {
        if (!demangled.empty()) {
            out << demangled << endl;
        }
        out << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, insn->op_str);
    }
}

void Binary::printBinary(std::ostream& out) {
    for (auto code : codes) {
        output(out, code, symtab);
    }
}

#define DEBUG 1

void logDebug(const std::string&);
void readSector(
        std::shared_ptr<iblessing::VirtualMemoryV2> &,
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
//    uc_engine *uc = memory->virtualMemory->getEngine();
//    uint64_t unicorn_sp_start = UnicornStackTopAddr;
//    uc_reg_write(uc, UC_ARM64_REG_SP, &unicorn_sp_start);
//    // set FPEN on CPACR_EL1
//    uint32_t fpen;
//    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
//    fpen |= 0x300000; // set FPEN bit
//    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &fpen);
//    logDebug("engine setted up");

    std::shared_ptr<VirtualMemoryV2> vm2 = memory->virtualMemory;
    this->symtab = macho->context->symtab;
    logDebug("symbol table built");
    this->stringtab = macho->context->strtab;
    logDebug("string table built");

    // dis all
    csh handle;
    assert(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // setup unicorn virtual memory
    uint64_t addr = textSect->addr;
    uint64_t end = textSect->addr + textSect->size;

    logDebug("virtual memory created");

    readSector(
            std::ref(vm2),
            std::ref(handle),
            std::ref(symtab),
            std::ref(codes),
            std::ref(symbols),
            addr,
            end
    );
}

void readSector(
        std::shared_ptr<iblessing::VirtualMemoryV2> &memory,
        csh &handle,
        std::shared_ptr<iblessing::SymbolTable> &symtab,
        std::vector<cs_insn *> &codes_container,
        std::map<uint64_t, iblessing::Symbol *> &symbol_container,
        uint64_t start_addr,
        uint64_t end_addr
) {
    uint64_t addr = start_addr;
    uint64_t size = end_addr - start_addr;
    while (addr < end_addr) {
        std::cout << std::setw(3) << (addr - start_addr)*100/size << "%\r";
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

//        uc_emu_start(uc, addr, addr + 4, 0, 1);
//        uc_emu_stop(uc);

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

std::shared_ptr<iblessing::StringTable> &BinaryReader::getStringTab() {
    return this->stringtab;
}

void logDebug(const std::string & message) {
    if (DEBUG == 1) {
        std::cout << message << std::endl;
    }
}

