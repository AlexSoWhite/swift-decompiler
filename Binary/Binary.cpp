//
// Created by nafanya on 11/24/22.
//
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <fstream>
#include <sstream>
#include "../swift/include/swift/Demangling/Demangle.h"
#include "Binary.h"
#include <iblessing-core/v2/objc/objc.hpp>

using namespace iblessing;
using namespace std;
using namespace swift;

string demange_symbol(Symbol * sym) {
    return Demangle::demangleSymbolAsString(
        sym->name.c_str(),
        strlen(sym->name.c_str()),
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
                string demangled = demange_symbol(sym);
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

void output(cs_insn *insn, const shared_ptr<SymbolTable> & symtab) {
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
        cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, demangled.c_str());
    } else {
        if (!demangled.empty()) {
            cout << demangled << endl;
        }
        cout << StringUtils::format("%016lx      %-8s %s\n", insn->address, insn->mnemonic, insn->op_str);
    }
}

void Binary::printBinary() {
    for (auto code : codes) {
        output(code, symtab);
    }
}
