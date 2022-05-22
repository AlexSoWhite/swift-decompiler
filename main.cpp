#include "cstring"
#include "Finders/Finder.h"

#define UnicornStackTopAddr      0x300000000

using namespace std;

enum regime {
    FUNCTIONS,
    VARIABLES,
    LOOPS,
    CONDITIONALS
};

int main(int argc, const char **argv) {
    if (argc != 3) {
        printf("usage: ./SwiftDecompiler [regime] [binary]\n");
        return 1;
    }
    string filePath = argv[2];
    regime r;
    if (strcmp(argv[1], "-f") == 0) {
        r = FUNCTIONS;
    } else if (strcmp(argv[1], "-v") == 0) {
        r = VARIABLES;
    } else if (strcmp(argv[1], "-l") == 0) {
        r = LOOPS;
    } else if (strcmp(argv[1], "-c") == 0) {
        r = CONDITIONALS;
    } else {
        printf("available regimes are -f, -v, -l or -c");
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
    }

    return 0;
}