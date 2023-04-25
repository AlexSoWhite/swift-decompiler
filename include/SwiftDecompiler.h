//
// Created by nafanya on 11/24/22.
//

#ifndef SWIFTDECOMPILER_SWIFTDECOMPILER_H
#define SWIFTDECOMPILER_SWIFTDECOMPILER_H

#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>

class Binary {
    std::vector<cs_insn *> codes;
    std::shared_ptr<iblessing::SymbolTable> symtab;
    std::shared_ptr<iblessing::StringTable> stringtab;
    std::vector<cs_insn *> search_for_symbol(const std::string &, bool);
public:
    Binary(
            const std::vector<cs_insn *> &codes,
            std::shared_ptr<iblessing::SymbolTable> &symtab,
            std::shared_ptr<iblessing::StringTable> &stringtab
    ) {
        this->codes = codes;
        this->symtab = symtab;
        this->stringtab = stringtab;
    }
    std::vector<cs_insn *> search_for_function(const std::string &);
    std::vector<cs_insn *> search_for_function_usages(const std::string &);
    std::vector<std::vector<cs_insn *>> search_for_loops();
    std::vector<cs_insn *> search_for_class(const std::string &);
    std::vector<cs_insn *> search_for_structure(const std::string &);
    std::vector<cs_insn *> search_for_constants(uint64_t);
    std::vector<std::string> get_strings(const std::string&, const std::string&);
    std::vector<std::string> get_sym_strings();
    void printBinary(std::ostream&);
};

class BinaryReader {
    std::shared_ptr<iblessing::Memory> memory;
    std::shared_ptr<iblessing::MachO> macho;
    std::vector<cs_insn *> codes;
    std::map<uint64_t, iblessing::Symbol *> symbols;
    std::shared_ptr<iblessing::SymbolTable> symtab;
    std::shared_ptr<iblessing::StringTable> stringtab;
    const long UnicornStackTopAddr = 0x300000000;
public:
    explicit BinaryReader(const std::string&);
    std::vector<cs_insn *>& getCodes();
    std::map<uint64_t, iblessing::Symbol*>& getSymbols();
    std::map<uint64_t, std::string>& getDemangledSymbols();
    std::shared_ptr<iblessing::SymbolTable>& getSymtab();
    std::shared_ptr<iblessing::StringTable>& getStringTab();
};


#endif //SWIFTDECOMPILER_SWIFTDECOMPILER_H
