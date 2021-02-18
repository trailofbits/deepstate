// Program Header Information ///////////////////////////
/**
 * @file BinaryParser.h
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Header File for the BinaryParser
 *
 * @details Contains function definitions for the BinaryParser
 *
 * @version 1.00
 *          Zane Fink
 *          Initial Development of the BinaryParser
 *
 */

#ifndef BINARY_PARSER_HH_INCLUDED
#define BINARY_PARSER_HH_INCLUDED

#include <bitset>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "BinaryIterator.h"

/**
 * Type alias byte to unsigned char 
 * to make its use more clear.
 **/
using byte = unsigned char;

/**
 * A BinaryParser reads unstructured binary data 
 * from a filestream and stores the data internally. 
 **/
class BinaryParser
{
 public:
    BinaryParser() = default;

    /**
     * Parse unstructured data from an input stream.
     * @param inputStream the stream to parse data from. 
     * @pre inputStream is a reference to a valid istream,
     *      so operations on it will be defined.
     * @post this->data will contain the binary data present in
     *       inputStream
     **/
    void parse( std::istream& inputStream );

    /**
     * Open a file with name 'fileName', and parse
     * the unstructured binary data from it.
     * @param fileName The name of the file to read.
     * @throws Exception if the file was not opened 
     *         successfully.
     * @post this->data will contain the binary data present in
     *       inputStream
     **/
    void parse( const std::string& fileName );

    /**
     * Returns a BinaryIterator object to iterate over
     * this BinaryParser's data. 
     * @throws std::runtime_error if this BinaryParser is 
     *         empty.
     * @returns BinaryIterator whose pointer is at the beginning 
     *          of this member's data.
     **/
    BinaryIterator getIterator();

 private:

    /**
     * Represents unstructured binary data.
     * Each byte is represented by an unsigned char.
     **/
    std::vector<byte> data;

    /**
     * Method to convert a string to unstructured binary 
     * data. This method takes the byte values in string 
     * and stores them in this->data.
     * @param string The string from which to take input.
     * @post data[ x ] = string[ x ] for x from zero to string.length() 
     **/
    void stringToData( const std::string& string );

    /**
     * Get unstructured binary data from a stream.
     * @param inputStream THe input stream to get the data 
     *        from.
     * @pre inputStream is a reference to a valid 
     *      inputStream, i.e. operations on inputStream
     *      are defined.
     **/
    void fromStream( std::istream& inputStream );
};

#endif // BINARY_PARSER_HH_INCLUDED
