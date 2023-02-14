#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#include <vector>
#include <iostream>
using std::vector;
using std::printf;

void _puthex(const char * name, const vector<unsigned char> & data)
{
    std::printf("%s (size %zu): ", name, data.size());
    for (int i = 0; i < data.size(); i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

void _puthex_n(const char * name, const vector<unsigned char> & data, size_t n)
{
    size_t k = std::min(n, data.size());
    std::printf("%s (size %zu): ", name, k);
    for (int i = 0; i < k; i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

#define puthex(var) _puthex(#var, var)

void _puthex_n(const char * name, const void * data, size_t n)
{
    std::printf("%s (size %zu): ", name, n);
    for (int i = 0; i < n; i++)
    {
        std::printf("%02x", ((uint8_t *)data)[i]);
    }
    std::printf("\n");
}

#define puthex_n(var, n) _puthex_n(#var, var, n)

#endif /* _TEST_COMMON_H_ */
