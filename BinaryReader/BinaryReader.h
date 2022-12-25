//
// Created by nafanya on 8/2/22.
//

#ifndef SWIFTDECOMPILER_BINARYREADER_H
#define SWIFTDECOMPILER_BINARYREADER_H

#include <iblessing-core/v2/vendor/capstone/capstone.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>

class BinaryReader {
    std::shared_ptr<iblessing::Memory> memory;
    std::shared_ptr<iblessing::MachO> macho;
    std::vector<cs_insn *> codes;
    std::map<uint64_t, iblessing::Symbol *> symbols;
    std::shared_ptr<iblessing::SymbolTable> symtab;
    const long UnicornStackTopAddr = 0x300000000;
public:
    explicit BinaryReader(const std::string&);
    std::vector<cs_insn *>& getCodes();
    std::map<uint64_t, iblessing::Symbol*>& getSymbols();
    std::map<uint64_t, std::string>& getDemangledSymbols();
    std::shared_ptr<iblessing::SymbolTable>& getSymtab();
};


#endif //SWIFTDECOMPILER_BINARYREADER_H
