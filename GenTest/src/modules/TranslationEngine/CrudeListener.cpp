// Program Header Information ///////////////////////////
/**
 * @file CrudeListener.cpp
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Main file for the Crude Listener class.
 *
 * @details Contains the implementation of the Crude Listener Interface. 
 *
 * @version 0.15
 *          Joshua Johnson ( 31 January 2020 )
 *          Initial incorporation of ANTLR library into GenTest codebase. 
 */

//#include "CrudeListener.h"

//void CrudeListener::enterDeepstate_noinline( GenTestParser::Deepstate_noinlineContext * ctx ) 
//{
//    // Initialize new node.
//    node newNode;

//    // Configure newNode.
//    newNode.type = DEEPSTATE_NOINLINE;
//    newNode.lineNum = ctx->getStart()->getLine();
//    newNode.colNum = ctx->getStop()->getStopIndex();
//    
//    // Push to back of vector.
//    CrudeListener::transList.push_back( newNode );
//}

//void CrudeListener::enterDs_assert( GenTestParser::Ds_assertContext * ctx )
//{
//    // Initialize new node.
//    node newNode;

//    // Configure newNode.
//    newNode.type = DEEPSTATE_ASSERT;
//    newNode.lineNum = ctx->getStart()->getLine();
//    newNode.colNum = ctx->getStop()->getStopIndex();
//    
//    // Push to back of vector.
//    CrudeListener::transList.push_back( newNode );
//}

//void CrudeListener::enterDs_assume( GenTestParser::Ds_assumeContext * ctx )
//{
//    // Initialize new node.
//    node newNode;

//    // Configure newNode.
//    newNode.type = DEEPSTATE_ASSUME;
//    newNode.lineNum = ctx->getStart()->getLine();
//    newNode.colNum = ctx->getStop()->getStopIndex();
//    
//    // Push to back of vector.
//    CrudeListener::transList.push_back( newNode );
//}

//void CrudeListener::enterDs_check( GenTestParser::Ds_checkContext * ctx )
//{
//    // Initialize new node.
//    node newNode;

//    // Configure newNode.
//    newNode.type = DEEPSTATE_CHECK;
//    newNode.lineNum = ctx->getStart()->getLine();
//    newNode.colNum = ctx->getStop()->getStopIndex();
//    
//    // Push to back of vector.
//    CrudeListener::transList.push_back( newNode );
//}

//void CrudeListener::enterSymbolic( GenTestParser::SymbolicContext * ctx )
//{
//    // Initialize new node.
//    node newNode;

//    // Configure newNode.
//    newNode.lineNum = ctx->getStart()->getLine();
//    newNode.colNum = ctx->getStop()->getStopIndex();
//    
//    // Push to back of vector.
//    CrudeListener::transList.push_back( newNode );

//    // Set flag.
//    CrudeListener::typeFlag = true;
//}

//void CrudeListener::enterType( GenTestParser::TypeContext * ctx )
//{
//    if( CrudeListener::typeFlag )
//    {
//        // Initialize pointer.
//        node * endPtr = &( CrudeListener::transList.at( CrudeListener::transList.size() - 1 ) );
//        std::string type = ctx->getStart()->getText();

//        // Initialize node to symbolic.
//        if( type.compare( "int" ) == 0 )
//        {
//            endPtr->type = X_INT;
//        }
//        else if( type.compare( "double" ) == 0 )
//        {
//            endPtr->type = X_DOUBLE;
//        }
//        else if( type.compare( "short" ) == 0 )
//        {
//            endPtr->type = X_SHORT;
//        }
//        else if( type.compare( "long" ) == 0 )
//        {
//            endPtr->type = X_LONG;
//        }
//        else if( type.compare( "uint8_t" ) == 0 )
//        {
//            endPtr->type = X_UINT8;
//        }
//        else if( type.compare( "uint16_t" ) == 0 )
//        {
//            endPtr->type = X_UINT16;
//        }
//        else if( type.compare( "uint32_t" ) == 0 )
//        {
//            endPtr->type = X_UINT32;
//        }
//        else if( type.compare( "uint64_t" ) == 0 )
//        {
//            endPtr->type = X_UINT64;
//        }
//        else if( type.compare( "char" ) == 0 )
//        {
//            endPtr->type = X_CHAR;
//        }
//        else if( type.compare( "float" ) == 0 )
//        {
//            endPtr->type = X_FLOAT;
//        }       
//        else if( type.compare( "unsigned" ) == 0 )
//        {
//            endPtr->type = X_UNSIGNED;
//        }

//        // Reset flag.
//        CrudeListener::typeFlag = false;
//    }
//}

//std::vector<node> CrudeListener::getList()
//{
//    return CrudeListener::transList;
//}


