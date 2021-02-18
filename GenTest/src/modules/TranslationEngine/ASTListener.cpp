#include "ASTListener.h"

#define INDENT 2

using namespace std;

vector<Node> ASTListener::getAST(){

    this->addToList( END_OF_FILE, "EOF" );

    return ASTListener::list;

}

// Private functions
void ASTListener::addToList( NTerminal type, std::string text )
{
    if( type == NO_TRANSLATE || type == INCLUDE 
        || type == STRUCT || type == TYPEDEF 
        || type == END_OF_FILE )
    {
        // Create a new node.
        Node newNode;

        // Set type and text.
        newNode.type = type;
        newNode.text = text;

        // Push to back of AST.
        ASTListener::list.push_back( newNode );
    }
    else if( ( type >= ASSERT_GT && type <= DEEPSTATE_CHECK ) 
               || type == SYMBOLIC )
    {
        // Remove node from back as it is a duplicate!
        if( list.at( list.size() - 1 ).type == NO_TRANSLATE )
        {
            list.pop_back();
        }
        // Create a new node.
        Node newNode;

        // Set type and text.
        newNode.type = type;
        newNode.text = text;

        // Push to back of AST.
        ASTListener::list.push_back( newNode );
    }
    else
    {
        ASTListener::list.at( list.size() - 1 ).type = type;
    }
}


// Non-target implementation.
void ASTListener::enterLine(GenTestParser::LineContext * ctx)
{
    this->addToList( NO_TRANSLATE, ctx->getText() );
}



// Target implementations.
void ASTListener::enterNoinline(GenTestParser::NoinlineContext * ctx)
{
    this->addToList( DEEPSTATE_NO_INLINE, ctx->getText() );
}

void ASTListener::enterDsinline(GenTestParser::DsinlineContext * ctx)
{
    this->addToList( DEEPSTATE_INLINE, ctx->getText() );
}

void ASTListener::enterDsnoreturn(GenTestParser::DsnoreturnContext * ctx)
{
    this->addToList( DEEPSTATE_NO_RETURN, ctx->getText() );
}


void ASTListener::enterAssrt(GenTestParser::AssrtContext * ctx )
{
    this->addToList( ASSERT, ctx->getText() );
}

void ASTListener::enterAssert_gt(GenTestParser::Assert_gtContext * ctx)
{
    this->addToList( ASSERT_GT, ctx->getText() );
}

void ASTListener::enterAssert_lt(GenTestParser::Assert_ltContext * ctx)
{
    this->addToList( ASSERT_LT, ctx->getText() );
}

void ASTListener::enterAssert_ge(GenTestParser::Assert_geContext * ctx)
{
   this->addToList( ASSERT_GE, ctx->getText() );
}


void ASTListener::enterAssert_le(GenTestParser::Assert_leContext * ctx)
{
    this->addToList( ASSERT_LE, ctx->getText() );
}

void ASTListener::enterAssert_ne(GenTestParser::Assert_neContext * ctx)
{
   this->addToList( ASSERT_NE, ctx->getText() );
}

void ASTListener::enterAssert_eq(GenTestParser::Assert_eqContext * ctx)
{
   this->addToList( ASSERT_EQ, ctx->getText() );
}


void ASTListener::enterAssume_gt(GenTestParser::Assume_gtContext * ctx)
{
    this->addToList( ASSUME_GT, ctx->getText() );
}

void ASTListener::enterAssume_lt(GenTestParser::Assume_ltContext * ctx)
{
    this->addToList( ASSUME_LT, ctx->getText() );
}

void ASTListener::enterAssume_ge(GenTestParser::Assume_geContext * ctx)
{
    this->addToList( ASSUME_GE, ctx->getText() );
}

void ASTListener::enterAssume_le(GenTestParser::Assume_leContext * ctx)
{
    this->addToList( ASSUME_LE, ctx->getText() );
}

void ASTListener::enterAssume_ne(GenTestParser::Assume_neContext * ctx)
{
    this->addToList( ASSUME_NE, ctx->getText() );
}

void ASTListener::enterAssume_eq(GenTestParser::Assume_eqContext * ctx)
{
    this->addToList( ASSUME_EQ, ctx->getText() );
}

void ASTListener::enterCheck_gt(GenTestParser::Check_gtContext * ctx)
{
    this->addToList( CHECK_GT, ctx->getText() );
}

void ASTListener::enterCheck_lt(GenTestParser::Check_ltContext * ctx)
{
    this->addToList( CHECK_LT, ctx->getText() );
}

void ASTListener::enterCheck_ge(GenTestParser::Check_geContext * ctx)
{
    this->addToList( CHECK_GE, ctx->getText() );
}

void ASTListener::enterCheck_le(GenTestParser::Check_leContext * ctx)
{
    this->addToList( CHECK_LE, ctx->getText() );
}

void ASTListener::enterCheck_ne(GenTestParser::Check_neContext * ctx)
{
    this->addToList( CHECK_NE, ctx->getText() );
}

void ASTListener::enterCheck_eq(GenTestParser::Check_eqContext * ctx)
{
    this->addToList( CHECK_EQ, ctx->getText() );
}


void ASTListener::enterDs_assert(GenTestParser::Ds_assertContext * ctx)
{
    this->addToList( DEEPSTATE_ASSERT, ctx->getText() );
}

void ASTListener::enterDs_assume(GenTestParser::Ds_assumeContext * ctx)
{
    this->addToList( DEEPSTATE_ASSUME, ctx->getText() );
}

void ASTListener::enterDs_check(GenTestParser::Ds_checkContext * ctx)
{
    this->addToList( DEEPSTATE_CHECK, ctx->getText() );
}

void ASTListener::enterLoop(GenTestParser::LoopContext * ctx)
{
    this->addToList( LOOP, ctx->getText() );
}

void ASTListener::enterFor_var(GenTestParser::For_varContext * ctx)
{
    this->list.at( list.size() - 1 ).list.push_back( ctx->getText() );
}

void ASTListener::enterFor_run(GenTestParser::For_runContext * ctx)
{
    this->list.at( list.size() - 1 ).list.push_back( ctx->getText() );
} 

void ASTListener::enterFor_inc(GenTestParser::For_incContext * ctx)
{
    this->list.at( list.size() - 1 ).list.push_back( ctx->getText() );
}

void ASTListener::enterDs_int(GenTestParser::Ds_intContext * ctx)
{
    this->addToList( DEEPSTATE_INT, ctx->getText() );
}

void ASTListener::enterDs_uint8(GenTestParser::Ds_uint8Context * ctx)
{
    this->addToList( DEEPSTATE_UINT8, ctx->getText() );
}

void ASTListener::enterDs_uint16(GenTestParser::Ds_uint16Context * ctx)
{
    this->addToList( DEEPSTATE_UINT16, ctx->getText() );
}

void ASTListener::enterDs_uint32(GenTestParser::Ds_uint32Context * ctx)
{
    this->addToList( DEEPSTATE_UINT32, ctx->getText() );
}

void ASTListener::enterDs_uint64(GenTestParser::Ds_uint64Context * ctx)
{
    this->addToList( DEEPSTATE_UINT64, ctx->getText() );
}

void ASTListener::enterDs_float(GenTestParser::Ds_floatContext * ctx)
{
    this->addToList( DEEPSTATE_FLOAT, ctx->getText() );
}

void ASTListener::enterDs_double(GenTestParser::Ds_doubleContext * ctx)
{
    this->addToList( DEEPSTATE_DOUBLE, ctx->getText() );
}

void ASTListener::enterDs_ushort(GenTestParser::Ds_ushortContext * ctx)
{
    this->addToList( DEEPSTATE_USHORT, ctx->getText() );
}

void ASTListener::enterDs_uchar(GenTestParser::Ds_ucharContext * ctx)
{
    this->addToList( DEEPSTATE_UCHAR, ctx->getText() );
}

void ASTListener::enterDs_c_str(GenTestParser::Ds_c_strContext * ctx)
{
    this->addToList( DEEPSTATE_C_STR, ctx->getText() );
}

void ASTListener::enterDs_c_struptolen(GenTestParser::Ds_c_struptolenContext * ctx)
{
    this->addToList( DEEPSTATE_C_STRUPTO, ctx->getText() );
}

void ASTListener::enterDs_malloc(GenTestParser::Ds_mallocContext * ctx)
{
    this->addToList( DEEPSTATE_MALLOC, ctx->getText() );
}

void ASTListener::enterTest(GenTestParser::TestContext * ctx)
{
    this->addToList( TEST, ctx->getText() );
}

void ASTListener::enterSymbolic(GenTestParser::SymbolicContext * ctx)
{
    this->addToList( SYMBOLIC, ctx->getText() );
}

void ASTListener::enterDs_char(GenTestParser::Ds_charContext * ctx)
{
    this->addToList( DEEPSTATE_CHAR, ctx->getText());
}

void ASTListener::enterType(GenTestParser::TypeContext * ctx)
{
    if( list.at( list.size() - 1 ).datatype.size() > 0 )
    {
        ASTListener::list.at( list.size() - 1 ).datatype += " " + ctx->getText();
    }
    else
    {
        ASTListener::list.at( list.size() - 1 ).datatype += ctx->getText();
    }
}

void ASTListener::enterDs_long(GenTestParser::Ds_longContext * ctx)
{
    this->addToList( DEEPSTATE_LONG, ctx->getText() );
}

void ASTListener::enterDs_short(GenTestParser::Ds_shortContext * ctx)
{
    this->addToList( DEEPSTATE_SHORT, ctx->getText() );
}

void ASTListener::enterDs_bool(GenTestParser::Ds_boolContext * ctx)
{
    this->addToList( DEEPSTATE_BOOL, ctx->getText() );
}


void ASTListener::enterDs_uint(GenTestParser::Ds_uintContext * ctx)
{
    this->addToList( DEEPSTATE_UINT, ctx->getText() );
}

void ASTListener::enterDs_int64(GenTestParser::Ds_int64Context * ctx)
{
    this->addToList( DEEPSTATE_INT64, ctx->getText() );
}

void ASTListener::enterInclude(GenTestParser::IncludeContext * ctx)
{
    this->addToList( INCLUDE, ctx->getText() );
}

void ASTListener::enterStructure(GenTestParser::StructureContext * ctx)
{
    if( this->list.at( list.size() - 1 ).type != TYPEDEF )
    {
        this->addToList( STRUCT, ctx->getText() );
    }
}

void ASTListener::enterType_definitions(GenTestParser::Type_definitionsContext * ctx)
{
    this->addToList( TYPEDEF, ctx->getText() );
}

