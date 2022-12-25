#include "cstring"
#include "BinaryReader/BinaryReader.h"
#include "Binary/Binary.h"
#include <sstream>

#define UnicornStackTopAddr      0x300000000

using namespace std;

enum regime {
    FUNCTIONS,
    LOOPS,
    CONDITIONALS,
    CONSTANTS,
    CLASSES,
    STRUCTURES
};

int main(int argc, const char **argv) {
    if (argc < 2) {
        cout << "specify the filename" << endl;
    }
    string filePath = argv[2];

    auto binaryReader = BinaryReader(filePath);

    auto binary = Binary(binaryReader.getCodes(), binaryReader.getSymtab());
    binary.printBinary();
    if (argc < 3) {
        cout <<"usage: ./SwiftDecompiler [regime] [binary] [options]" << endl;
        return 1;
    }
    regime r;
    if (strcmp(argv[1], "-functions") == 0) {
        r = FUNCTIONS;
    } else if (strcmp(argv[1], "-loops") == 0) {
        r = LOOPS;
    } else if (strcmp(argv[1], "-conditionals") == 0) {
        r = CONDITIONALS;
    } else if (strcmp(argv[1], "-constants") == 0) {
        r = CONSTANTS;
    } else if (strcmp(argv[1], "-class") == 0) {
        r = CLASSES;
    } else if (strcmp(argv[1], "-struct") == 0) {
        r = STRUCTURES;
    } else {
        printf("available regimes are -functions, -variables, -loops, -conditionals or -constants");
    }

    string name;
    switch (r) {
        case FUNCTIONS:
            cin>> name;
            Binary(binary.search_for_function(name), binaryReader.getSymtab()).printBinary();
            break;
        case LOOPS:
            for (const auto& loop : binary.search_for_loops()) {
                cout << "next loop: " << endl;
                Binary(loop, binaryReader.getSymtab()).printBinary();
                cout << endl << endl;
            }
            break;
        case CONDITIONALS:
            //Finder::find_conditionals(filePath);
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
            cout << endl << "your value: " << endl;
            Binary(binary.search_for_constants(value), binaryReader.getSymtab()).printBinary();
            cout << endl;
            break;
        case CLASSES:
            cin >> name;
            Binary(binary.search_for_class(name), binaryReader.getSymtab()).printBinary();
            break;
        case STRUCTURES:
            cin >> name;
            Binary(binary.search_for_structure(name), binaryReader.getSymtab()).printBinary();
            break;
    }

    return 0;
}