#ifndef SWIFTDECOMPILER_FINDER_H
#define SWIFTDECOMPILER_FINDER_H

#include <string>

using namespace std;
class Finder {
public:
    static void find_functions(const string & path);
    static void find_loops(const string & path);
    static void find_variables(const string & path);
    static void find_conditionals(const string & path);
    static void find_constants(const string & path, uint64_t value);
};


#endif //SWIFTDECOMPILER_FINDER_H
