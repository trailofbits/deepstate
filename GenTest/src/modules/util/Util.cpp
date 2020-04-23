// Program Information //////////////////////////////////////////////
/**
  * @file Util.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Utility classes/functions go here
  *
  * @details This file will contain utility functions or classes that dont necessarily have
  *          another location to be.
  *
  * @version 0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout
  (Legal terms of use/libraries used need to be added here once we get to that point)
**/

#include "Util.h"

std::string stripWhiteSpace( const std::string& toStrip )
{
    int startSpaces = 0, endSpaces = 0;

    auto cStr = toStrip.c_str();

    for( int index = 0; index < toStrip.length(); index++ )
    {
        char currentChar = cStr[index];

        if( currentChar == ' ' || currentChar == '\t' )
        {
            //still in starting spaces
            if( startSpaces == endSpaces )
            {
                startSpaces++;

                endSpaces++;
            }
        }
        else
        {
            endSpaces = index + 1;
        }
    }

    return toStrip.substr( startSpaces, endSpaces-startSpaces );
}

std::string stripNewLine( std::string stringToStrip )
{
    while( stringToStrip.find('\n') != std::string::npos )
    {
        auto location = stringToStrip.find('\n');

        stringToStrip.erase( location, 1 );
    }
    return stringToStrip;
}

std::string generatePadding( int depth )
{
    return std::string(depth, '\t');
}

int commaLocation( const std::string& toFind )
{
    const char * cStr = toFind.c_str();

    int currentDepth = 0;

    for( int index = 0; index < toFind.length(); index++ )
    {
        char current = cStr[index];

        if( current == '(') currentDepth++;
        else if (current == ')' ) currentDepth--;
        else if (current == ',' )
        {
            if( currentDepth == 0 )
            {
                return index;
            }
        }
    }

    return 0;
}

std::string whichStructInLine( std::string lineToCheck, std::vector<std::string> vectorToSearch )
{
    auto currentSearch = vectorToSearch.begin();

    //TODO: Make this more robust

    for( int current = 0; current < vectorToSearch.size(); current++ )
    {
        std::string currentString = (*currentSearch);

        if( lineToCheck.find( currentString ) != std::string::npos )
        {
            return currentString;
        }

        currentSearch++;
    }

    return "";
}

