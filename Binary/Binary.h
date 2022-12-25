//
// Created by nafanya on 11/24/22.
//

#ifndef SWIFTDECOMPILER_BINARY_H
#define SWIFTDECOMPILER_BINARY_H

#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>

class Binary {
    std::vector<cs_insn *> codes;
    std::shared_ptr<iblessing::SymbolTable> symtab;
    std::vector<cs_insn *> search_for_symbol(const std::string &, bool);
public:
    Binary(const std::vector<cs_insn *> &codes, std::shared_ptr<iblessing::SymbolTable> &symtab) {
        this->codes = codes;
        this->symtab = symtab;
    }
    std::vector<cs_insn *> search_for_function(const std::string &);
    std::vector<cs_insn *> search_for_function_usages(const std::string &);
    std::vector<std::vector<cs_insn *>> search_for_loops();
    std::vector<cs_insn *> search_for_class(const std::string &);
    std::vector<cs_insn *> search_for_structure(const std::string &);
    std::vector<cs_insn *> search_for_constants(uint64_t);
    void printBinary();
};


#endif //SWIFTDECOMPILER_BINARY_H
