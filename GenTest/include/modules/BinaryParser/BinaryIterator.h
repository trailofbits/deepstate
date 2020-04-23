// Program Header Information ///////////////////////////
/**
 * @file BinaryIterator.h
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Header file for BinaryIterator class
 *
 * @details Contains function definitions for the BinaryIterator
 *
 * @version 1.00
 *          Zane Fink
 *          Initial development of the BinaryIterator Class
 *
 */

#ifndef BINARY_ITERATOR_HH_INCLUDED
#define BINARY_ITERATOR_HH_INCLUDED
#include <vector>
#include <string>
#include <cstddef>
#include <stdexcept>

using byte = unsigned char;

/**
 * A BinaryIterator enables the retrieval of 
 * concrete data from unstructured binary data. 
 **/
class BinaryIterator
{
 public:
    /**
     * Create a BinaryIterator with a pointer to 
     * data.
     * @param data A pointer to the data vector 
     *        this object will iterate over.
     **/
    BinaryIterator( std::vector<byte> *data )
        : dataPtr( data ), index( 0 ) {}

    /**
     * Get the next item from the binary data.
     * Template type allows for the retrieval of 
     * different types from the same data.     
     * @note this method advances the iterator
     * @throws std::runtime_error if there is not enough
     *         space for another member of type T.
     * @returns T initialized from the unstructured
     *          binary data
     **/
    template <typename T>
        T next()
        {
            // ensure we have at least one more T in our
            // data
            if( index < dataPtr->size()
                && ( dataPtr->size() - index ) >= sizeof( T ) 
              )
                {
                    // TODO: endianness?
					std::size_t val_idx = index;
					index += sizeof( T );
                    return T( *(T*) &((*dataPtr)[0]) + val_idx );
                }
            throw std::runtime_error( "Specified type requested is larger than "
                                      "the remaining memory."
                                      );
        }

    /**
     * Rewind the iterator back one position.
     * This is equivalent to calling
     * BinaryIterator::rewind( 1 )
     **/
    void rewind();

    /**
     * Rewind the iterator's pointer back
     * step bytes.
     * @param step the number of bytes to rewind the
     *        iterator.
     * @note If step > index, the iterator
     *       points to the 0'th position.
     **/
    void rewind( std::size_t step );

    // Begin template specializations for primitive types

    /**
     * Get the next integer from the BinaryIterator
     * @returns an integer from the Iterator's data.
     **/
    int nextInt();

    /**
     * Get the next unsigned integer fro mthe BinaryIterator
     * @return an unsigned integer from the Iterator's data.
     */
    unsigned int nextUInt();

    /**
     * Get the next unsigned char from the BinaryIterator
     * @returns an unsigned char from the Iterator's data.
     **/
    unsigned char nextUChar();

    /**
     * Get the next char from the BinaryIterator
     * @return a char from the Iterator's data.
     */
    char nextChar();

    /**
     * Get the next size_t from the BinaryIterator
     * @returns a size_t from the Iterator's data.
     **/
    std::size_t nextSize_t();

    /**
     * Get the next uint64_t from the BinaryIterator
     * @returns a uint64_t from the Iterator's data.
     **/
    std::uint64_t nextUInt64();

    /**
     * Get the next int64_t from the BinaryIterator
     * @returns a int64_t from the Iterator's data.
     **/
    std::int64_t nextInt64();

    /**
     * Get the next uint16_t from the BinaryIterator
     * @returns a uint16_t from the Iterator's data.
     **/
    std::uint16_t nextUInt16();

    /**
     * Get the next int16_t from the BinaryIterator
     * @returns a int16_t from the Iterator's data.
     **/
    std::int16_t nextInt16();

    /**
     * Get the next long from the BinaryIterator
     * @returns a long from the Iterator's data.
     **/
    long nextLong();

    /**
     * Get the next float from the BinaryIterator
     * @returns a float from the Iterator's data.
     **/
    float nextFloat();

    /**
     * Get the next double from the BinaryIterator
     * @returns a double from the Iterator's data.
     **/
    double nextDouble();

    /**
     * Get the next short from the BinaryIterator
     * @returns a short from the Iterator's data.
     **/
    short nextShort();

    /**
     * Return the next random int from the BinaryIterator.
     * @returns a random integer from the Iterator's data.
     **/
    int nextRandInt();

    /**
     * Return the next boolean value from the BinaryIterator.
     * @returns a boolean value from the Iterator's data.
     **/
    bool nextBool();


    /**
     * Return the next string value from the BinaryIterator.
     * @param len The length of the string to return
     * @param allowed An optional pointer to string containing characters 
     *        that are allowed in the output string. 
     *        If any characters are to be allowed, 
     *        pass a pointer to null. 
     * @returns a string value from the Iterator's data.
     **/
    std::string nextString( std::size_t len, const char *allowed );

 private:
    /**
     * A pointer to unstructured binary data.
     **/
    std::vector<byte> *dataPtr;

    /**
     * The current index of the iterator.
     **/
    std::size_t index;
};

#endif // BINARY_ITERATOR_HH_INCLUDED
