// Program Information //////////////////////////////////////////////
/**
  * @file DataStructures.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Storage of different data structure classes
  *
  * @details This class will be used for the creation and storage for code
  *           relating to created data structures
  *
  * @version 0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout

  (Legal terms of use/libraries used need to be added here once we get to that point)

**/

// data structures go here as needed ( we can split these into separate files for readability if need be )

#include "DataStructures.h"


//Translation Dictionary Methods
bool TranslationDictionary::loadFile( const std::string& filePath )
{
    configFile.open( filePath );

    //loops over each line of cfg file
    while( !configFile.eof() )
    {
        std::string currentTrans, nTerminal, translateTo;

        std::getline( configFile, currentTrans );

        auto location = currentTrans.find('=');

        //if invalid translation
        if( location == std::string::npos )
        {
            //log if this happens
        }
        else
        {
            nTerminal = currentTrans.substr(0, location );

            translateTo = currentTrans.substr( location + 1 );

            //replaces all "unnatural new lines" mainly for MAIN_FUNC
            while( translateTo.find('\\') != std::string::npos )
            {
                auto locationOfNewLine = translateTo.find_first_of('\\');

                translateTo = translateTo.substr(0,locationOfNewLine) + '\n'
                              + translateTo.substr(locationOfNewLine+2, translateTo.length());
            }

            TranslationEntry newEntry;

            newEntry.nTerminalVal = nTerminal;

            newEntry.translateTo = translateTo;

            newEntry.newEntry = false;

            translations.push_back( newEntry );
        }


    }

    configFile.close();

    return populateNTerminals();
}

TranslationEntry TranslationDictionary::findTranslationFromNTerminal( NonTerminals NTerminalToFind )
{
    TranslationEntry output = TranslationEntry();

    for( auto & translation : translations )
    {
        if( translation.nTerminal == NTerminalToFind )
        {
            output = translation;
        }
    }

    return output;
}

/**
 * Private method to populate the translation entries with their proper NTerminal
 * @return If the population was successful.
 */
bool TranslationDictionary::populateNTerminals()
{
    auto it = vitalTranslations.begin();

    while( it != vitalTranslations.end() )
    {
        std::string currentNTerminalVal = it->first;

        NTerminal currentNTerminal = it->second;

        bool populated = assignTranslation( currentNTerminalVal, currentNTerminal );

        //if a vitalTranslation wasn't populated
        if( !populated )
        {
            //TODO: Log vital translation not being populated

            return false;
        }
        //increment the iterator for the next vital translation
        it++;

    }
    auto nonVitalIt = nonVital.begin();

    while( nonVitalIt != nonVital.end() )
    {
        std::string currentNTerminalVal = nonVitalIt->first;

        NTerminal currentNTerminal = nonVitalIt->second;

        bool populated = assignTranslation( currentNTerminalVal, currentNTerminal );

        if( !populated )
        {
            //TODO: Log if a non vital translation is missing
        }

        nonVitalIt++;
    }

    return true;
}

bool TranslationDictionary::assignTranslation(std::string translationString, NTerminal currentNTerminal )
{
    bool added = false;

    for( int index = 0; index < translations.size(); index++ )
    {
        if( translations[ index ].nTerminalVal == translationString )
        {
            translations[ index ].nTerminal = currentNTerminal;

            translations[ index ].translationAdded = true;

            added = true;
        }
    }

    return added;
}

