#include "unistd.h"
#include <iostream>

using namespace std;

extern void printTest();

class Test {
public:
    Test(): num(0) {}
    ~Test() {
        cout << "destructor: 0x" << hex << num << endl;
    }

    void test(int i) {
        this->num++;
        cout << "test is " << i << endl;
    }

private:
    int num;
};

void test_func(int a) {
    cout << "func is " << a << endl;
}

int main() {
    Test test;

    cout << "child process start" << endl;
    for (int i = 0 ; i < 10 ; ++i) {
        test_func(i);
        test.test(i);
        usleep(1000 * 100); // 100ms
    }
    printTest();
    cout << "child process end" << endl;

    return 0;
}
