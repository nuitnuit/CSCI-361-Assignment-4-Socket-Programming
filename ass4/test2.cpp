#include<iostream>

using namespace std;

int main() {
    char c[] = {'a', 'b', 'c', 'd', 'e'};
    char d[] = {'g', 'h', 'i', 'j', 'k'};
    string s = "";
    s = c;
    s += d;
    cout << s << endl;
}