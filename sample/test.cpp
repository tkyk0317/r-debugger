#include <iostream>

using namespace std;

static int global_variable = 0x12239999;
static short global_short = 0x1188;

void printTest() {
    cout << "print test function" << endl;
    cout << "global_variable: 0x" << hex << global_variable << endl;
    cout << "global_short: 0x" << hex << global_short << endl;
}

