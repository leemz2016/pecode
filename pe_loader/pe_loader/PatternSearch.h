#pragma once

#include "Types.h"

#include <string>
#include <vector>
#include <initializer_list>

namespace magic
{

class PatternSearch
{
public:
     PatternSearch( const std::vector<uint8_t>& pattern );
     PatternSearch( const std::initializer_list<uint8_t>&& pattern );
     PatternSearch( const std::string& pattern );
     PatternSearch( const char* pattern, size_t len = 0 );
     PatternSearch( const uint8_t* pattern, size_t len = 0 );

     ~PatternSearch();

    /// <summary>
    /// Default pattern matching with wildcards.
    /// std::search is approximately 2x faster than naive approach.
    /// </summary>
    /// <param name="wildcard">Pattern wildcard</param>
    /// <param name="scanStart">Starting address</param>
    /// <param name="scanSize">Size of region to scan</param>
    /// <param name="out">Found results</param>
    /// <param name="value_offset">Value that will be added to resulting addresses</param>
    /// <returns>Number of found addresses</returns>
     size_t Search( uint8_t wildcard, void* scanStart, size_t scanSize, std::vector<ptr_t>& out, ptr_t value_offset = 0 );

    /// <summary>
    /// Full pattern match, no wildcards.
    /// Uses Boyer–Moore–Horspool algorithm.
    /// </summary>
    /// <param name="scanStart">Starting address</param>
    /// <param name="scanSize">Size of region to scan</param>
    /// <param name="out">Found results</param>
    /// <param name="value_offset">Value that will be added to resulting addresses</param>
    /// <returns>Number of found addresses</returns>
     size_t Search( void* scanStart, size_t scanSize, std::vector<ptr_t>& out, ptr_t value_offset = 0 );

private:
    std::vector<uint8_t> _pattern;      // Pattern to search
};

}