#include "antlr4-runtime.h"
#include "GenTestBaseListener.h"
#include "stdlib.h"
#include "DataStructures.h"
#include <string>

class ASTListener : public GenTestBaseListener
{
    std::vector<Node> list;

    void addToList( NTerminal type, std::string text );

    public: 
          std::vector<Node> getAST();

	  // Target rules.
          void enterNoinline(GenTestParser::NoinlineContext * ctx);
	  void enterLine(GenTestParser::LineContext * ctx);
	  void enterDsinline(GenTestParser::DsinlineContext * ctx);
	  void enterDsnoreturn(GenTestParser::DsnoreturnContext * ctx);

	  void enterAssume_gt(GenTestParser::Assume_gtContext * ctx);
	  void enterAssume_lt(GenTestParser::Assume_ltContext * ctx);
	  void enterAssume_ge(GenTestParser::Assume_geContext * ctx);
	  void enterAssume_le(GenTestParser::Assume_leContext * ctx);
	  void enterAssume_ne(GenTestParser::Assume_neContext * ctx);
	  void enterAssume_eq(GenTestParser::Assume_eqContext * ctx);

	  void enterAssrt(GenTestParser::AssrtContext * ctx );
	  void enterAssert_gt(GenTestParser::Assert_gtContext * ctx);
	  void enterAssert_lt(GenTestParser::Assert_ltContext * ctx);
	  void enterAssert_ge(GenTestParser::Assert_geContext * ctx);
	  void enterAssert_le(GenTestParser::Assert_leContext * ctx);
	  void enterAssert_ne(GenTestParser::Assert_neContext * ctx);
	  void enterAssert_eq(GenTestParser::Assert_eqContext * ctx);

	  void enterCheck_gt(GenTestParser::Check_gtContext * ctx);
	  void enterCheck_lt(GenTestParser::Check_ltContext * ctx);
	  void enterCheck_ge(GenTestParser::Check_geContext * ctx);
	  void enterCheck_le(GenTestParser::Check_leContext * ctx);
	  void enterCheck_ne(GenTestParser::Check_neContext * ctx);
	  void enterCheck_eq(GenTestParser::Check_eqContext * ctx);

 	  void enterDs_assume(GenTestParser::Ds_assumeContext * ctx);
	  void enterDs_assert(GenTestParser::Ds_assertContext * ctx);
	  void enterDs_check(GenTestParser::Ds_checkContext * ctx);

	  void enterLoop(GenTestParser::LoopContext * ctx);
	  void enterFor_var(GenTestParser::For_varContext * ctx);
	  void enterFor_run(GenTestParser::For_runContext * ctx);
	  void enterFor_inc(GenTestParser::For_incContext * ctx);

	  void enterDs_int(GenTestParser::Ds_intContext * ctx);
	  void enterDs_uint8(GenTestParser::Ds_uint8Context * ctx);
	  void enterDs_uint16(GenTestParser::Ds_uint16Context * ctx);
	  void enterDs_uint32(GenTestParser::Ds_uint32Context * ctx);
	  void enterDs_uint64(GenTestParser::Ds_uint64Context * ctx);
	  void enterDs_float(GenTestParser::Ds_floatContext * ctx);
	  void enterDs_double(GenTestParser::Ds_doubleContext * ctx);
	  void enterDs_ushort(GenTestParser::Ds_ushortContext * ctx);
	  void enterDs_uchar(GenTestParser::Ds_ucharContext * ctx);
	  void enterDs_char(GenTestParser::Ds_charContext * ctx);
	  void enterDs_c_str(GenTestParser::Ds_c_strContext * ctx);
	  void enterDs_c_struptolen(GenTestParser::Ds_c_struptolenContext * ctx);
	  void enterDs_malloc(GenTestParser::Ds_mallocContext * ctx);

	  void enterDs_long(GenTestParser::Ds_longContext * ctx);
	  void enterDs_short(GenTestParser::Ds_shortContext * ctx);
	  void enterDs_bool(GenTestParser::Ds_boolContext * ctx);
	  void enterDs_uint(GenTestParser::Ds_uintContext * ctx);
	  void enterDs_int64(GenTestParser::Ds_int64Context * ctx);

	  void enterTest(GenTestParser::TestContext * ctx);
	  void enterSymbolic(GenTestParser::SymbolicContext * ctx);
	  void enterType(GenTestParser::TypeContext * ctx);
	  void enterInclude(GenTestParser::IncludeContext * ctx);
	  void enterStructure(GenTestParser::StructureContext * ctx);
	  void enterType_definitions(GenTestParser::Type_definitionsContext * ctx);
};
