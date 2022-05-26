#include "cstring"
#include "Finders/Finder.h"
#include <sstream>

#define UnicornStackTopAddr      0x300000000

using namespace std;

enum regime {
    FUNCTIONS,
    VARIABLES,
    LOOPS,
    CONDITIONALS,
    CONSTANTS
};

int main(int argc, const char **argv) {
    if (argc < 3) {
        printf("usage: ./SwiftDecompiler [regime] [binary] [options]\n");
        return 1;
    }
    string filePath = argv[2];
    regime r;
    if (strcmp(argv[1], "-functions") == 0) {
        r = FUNCTIONS;
    } else if (strcmp(argv[1], "-variables") == 0) {
        r = VARIABLES;
    } else if (strcmp(argv[1], "-loops") == 0) {
        r = LOOPS;
    } else if (strcmp(argv[1], "-conditionals") == 0) {
        r = CONDITIONALS;
    } else if (strcmp(argv[1], "-constants") == 0) {
        r = CONSTANTS;
    } else {
        printf("available regimes are -functions, -variables, -loops, -conditionals or -constants");
    }

    switch (r) {
        case FUNCTIONS:
            Finder::find_functions(filePath);
            break;
        case VARIABLES:
            Finder::find_variables(filePath);
            break;
        case LOOPS:
            Finder::find_loops(filePath);
            break;
        case CONDITIONALS:
            Finder::find_conditionals(filePath);
            break;
        case CONSTANTS:
            uint64_t value;
            if (argc != 4) {
                printf("usage: ./SwiftDecompiler -constants [binary] [hex-value]\n");
                break;
            } else {
                stringstream ss;
                ss << argv[3];
                ss >> std::hex >> value;
            }
            Finder::find_constants(filePath, value);
            break;
    }

    return 0;
}