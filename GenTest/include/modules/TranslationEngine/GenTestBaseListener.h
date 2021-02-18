
// Generated from GenTest.g4 by ANTLR 4.8

#pragma once


#include "antlr4-runtime.h"
#include "GenTestListener.h"


/**
 * This class provides an empty implementation of GenTestListener,
 * which can be extended to create a listener which only needs to handle a subset
 * of the available methods.
 */
class  GenTestBaseListener : public GenTestListener {
public:

  virtual void enterFile(GenTestParser::FileContext * /*ctx*/) override { }
  virtual void exitFile(GenTestParser::FileContext * /*ctx*/) override { }

  virtual void enterLine(GenTestParser::LineContext * /*ctx*/) override { }
  virtual void exitLine(GenTestParser::LineContext * /*ctx*/) override { }

  virtual void enterType(GenTestParser::TypeContext * /*ctx*/) override { }
  virtual void exitType(GenTestParser::TypeContext * /*ctx*/) override { }

  virtual void enterTarget(GenTestParser::TargetContext * /*ctx*/) override { }
  virtual void exitTarget(GenTestParser::TargetContext * /*ctx*/) override { }

  virtual void enterComment(GenTestParser::CommentContext * /*ctx*/) override { }
  virtual void exitComment(GenTestParser::CommentContext * /*ctx*/) override { }

  virtual void enterLoop(GenTestParser::LoopContext * /*ctx*/) override { }
  virtual void exitLoop(GenTestParser::LoopContext * /*ctx*/) override { }

  virtual void enterFor_var(GenTestParser::For_varContext * /*ctx*/) override { }
  virtual void exitFor_var(GenTestParser::For_varContext * /*ctx*/) override { }

  virtual void enterFor_run(GenTestParser::For_runContext * /*ctx*/) override { }
  virtual void exitFor_run(GenTestParser::For_runContext * /*ctx*/) override { }

  virtual void enterFor_inc(GenTestParser::For_incContext * /*ctx*/) override { }
  virtual void exitFor_inc(GenTestParser::For_incContext * /*ctx*/) override { }

  virtual void enterInclude(GenTestParser::IncludeContext * /*ctx*/) override { }
  virtual void exitInclude(GenTestParser::IncludeContext * /*ctx*/) override { }

  virtual void enterType_definitions(GenTestParser::Type_definitionsContext * /*ctx*/) override { }
  virtual void exitType_definitions(GenTestParser::Type_definitionsContext * /*ctx*/) override { }

  virtual void enterStructure(GenTestParser::StructureContext * /*ctx*/) override { }
  virtual void exitStructure(GenTestParser::StructureContext * /*ctx*/) override { }

  virtual void enterNoinline(GenTestParser::NoinlineContext * /*ctx*/) override { }
  virtual void exitNoinline(GenTestParser::NoinlineContext * /*ctx*/) override { }

  virtual void enterDsinline(GenTestParser::DsinlineContext * /*ctx*/) override { }
  virtual void exitDsinline(GenTestParser::DsinlineContext * /*ctx*/) override { }

  virtual void enterDsnoreturn(GenTestParser::DsnoreturnContext * /*ctx*/) override { }
  virtual void exitDsnoreturn(GenTestParser::DsnoreturnContext * /*ctx*/) override { }

  virtual void enterAssume_gt(GenTestParser::Assume_gtContext * /*ctx*/) override { }
  virtual void exitAssume_gt(GenTestParser::Assume_gtContext * /*ctx*/) override { }

  virtual void enterAssume_lt(GenTestParser::Assume_ltContext * /*ctx*/) override { }
  virtual void exitAssume_lt(GenTestParser::Assume_ltContext * /*ctx*/) override { }

  virtual void enterAssume_ge(GenTestParser::Assume_geContext * /*ctx*/) override { }
  virtual void exitAssume_ge(GenTestParser::Assume_geContext * /*ctx*/) override { }

  virtual void enterAssume_le(GenTestParser::Assume_leContext * /*ctx*/) override { }
  virtual void exitAssume_le(GenTestParser::Assume_leContext * /*ctx*/) override { }

  virtual void enterAssume_eq(GenTestParser::Assume_eqContext * /*ctx*/) override { }
  virtual void exitAssume_eq(GenTestParser::Assume_eqContext * /*ctx*/) override { }

  virtual void enterAssume_ne(GenTestParser::Assume_neContext * /*ctx*/) override { }
  virtual void exitAssume_ne(GenTestParser::Assume_neContext * /*ctx*/) override { }

  virtual void enterAssrt(GenTestParser::AssrtContext * /*ctx*/) override { }
  virtual void exitAssrt(GenTestParser::AssrtContext * /*ctx*/) override { }

  virtual void enterAssert_gt(GenTestParser::Assert_gtContext * /*ctx*/) override { }
  virtual void exitAssert_gt(GenTestParser::Assert_gtContext * /*ctx*/) override { }

  virtual void enterAssert_lt(GenTestParser::Assert_ltContext * /*ctx*/) override { }
  virtual void exitAssert_lt(GenTestParser::Assert_ltContext * /*ctx*/) override { }

  virtual void enterAssert_ge(GenTestParser::Assert_geContext * /*ctx*/) override { }
  virtual void exitAssert_ge(GenTestParser::Assert_geContext * /*ctx*/) override { }

  virtual void enterAssert_le(GenTestParser::Assert_leContext * /*ctx*/) override { }
  virtual void exitAssert_le(GenTestParser::Assert_leContext * /*ctx*/) override { }

  virtual void enterAssert_eq(GenTestParser::Assert_eqContext * /*ctx*/) override { }
  virtual void exitAssert_eq(GenTestParser::Assert_eqContext * /*ctx*/) override { }

  virtual void enterAssert_ne(GenTestParser::Assert_neContext * /*ctx*/) override { }
  virtual void exitAssert_ne(GenTestParser::Assert_neContext * /*ctx*/) override { }

  virtual void enterCheck_gt(GenTestParser::Check_gtContext * /*ctx*/) override { }
  virtual void exitCheck_gt(GenTestParser::Check_gtContext * /*ctx*/) override { }

  virtual void enterCheck_lt(GenTestParser::Check_ltContext * /*ctx*/) override { }
  virtual void exitCheck_lt(GenTestParser::Check_ltContext * /*ctx*/) override { }

  virtual void enterCheck_ge(GenTestParser::Check_geContext * /*ctx*/) override { }
  virtual void exitCheck_ge(GenTestParser::Check_geContext * /*ctx*/) override { }

  virtual void enterCheck_le(GenTestParser::Check_leContext * /*ctx*/) override { }
  virtual void exitCheck_le(GenTestParser::Check_leContext * /*ctx*/) override { }

  virtual void enterCheck_eq(GenTestParser::Check_eqContext * /*ctx*/) override { }
  virtual void exitCheck_eq(GenTestParser::Check_eqContext * /*ctx*/) override { }

  virtual void enterCheck_ne(GenTestParser::Check_neContext * /*ctx*/) override { }
  virtual void exitCheck_ne(GenTestParser::Check_neContext * /*ctx*/) override { }

  virtual void enterDs_assume(GenTestParser::Ds_assumeContext * /*ctx*/) override { }
  virtual void exitDs_assume(GenTestParser::Ds_assumeContext * /*ctx*/) override { }

  virtual void enterDs_assert(GenTestParser::Ds_assertContext * /*ctx*/) override { }
  virtual void exitDs_assert(GenTestParser::Ds_assertContext * /*ctx*/) override { }

  virtual void enterDs_check(GenTestParser::Ds_checkContext * /*ctx*/) override { }
  virtual void exitDs_check(GenTestParser::Ds_checkContext * /*ctx*/) override { }

  virtual void enterDs_int(GenTestParser::Ds_intContext * /*ctx*/) override { }
  virtual void exitDs_int(GenTestParser::Ds_intContext * /*ctx*/) override { }

  virtual void enterDs_int8(GenTestParser::Ds_int8Context * /*ctx*/) override { }
  virtual void exitDs_int8(GenTestParser::Ds_int8Context * /*ctx*/) override { }

  virtual void enterDs_int16(GenTestParser::Ds_int16Context * /*ctx*/) override { }
  virtual void exitDs_int16(GenTestParser::Ds_int16Context * /*ctx*/) override { }

  virtual void enterDs_int64(GenTestParser::Ds_int64Context * /*ctx*/) override { }
  virtual void exitDs_int64(GenTestParser::Ds_int64Context * /*ctx*/) override { }

  virtual void enterDs_uint(GenTestParser::Ds_uintContext * /*ctx*/) override { }
  virtual void exitDs_uint(GenTestParser::Ds_uintContext * /*ctx*/) override { }

  virtual void enterDs_uint8(GenTestParser::Ds_uint8Context * /*ctx*/) override { }
  virtual void exitDs_uint8(GenTestParser::Ds_uint8Context * /*ctx*/) override { }

  virtual void enterDs_uint16(GenTestParser::Ds_uint16Context * /*ctx*/) override { }
  virtual void exitDs_uint16(GenTestParser::Ds_uint16Context * /*ctx*/) override { }

  virtual void enterDs_uint32(GenTestParser::Ds_uint32Context * /*ctx*/) override { }
  virtual void exitDs_uint32(GenTestParser::Ds_uint32Context * /*ctx*/) override { }

  virtual void enterDs_uint64(GenTestParser::Ds_uint64Context * /*ctx*/) override { }
  virtual void exitDs_uint64(GenTestParser::Ds_uint64Context * /*ctx*/) override { }

  virtual void enterDs_float(GenTestParser::Ds_floatContext * /*ctx*/) override { }
  virtual void exitDs_float(GenTestParser::Ds_floatContext * /*ctx*/) override { }

  virtual void enterDs_double(GenTestParser::Ds_doubleContext * /*ctx*/) override { }
  virtual void exitDs_double(GenTestParser::Ds_doubleContext * /*ctx*/) override { }

  virtual void enterDs_long(GenTestParser::Ds_longContext * /*ctx*/) override { }
  virtual void exitDs_long(GenTestParser::Ds_longContext * /*ctx*/) override { }

  virtual void enterDs_short(GenTestParser::Ds_shortContext * /*ctx*/) override { }
  virtual void exitDs_short(GenTestParser::Ds_shortContext * /*ctx*/) override { }

  virtual void enterDs_ushort(GenTestParser::Ds_ushortContext * /*ctx*/) override { }
  virtual void exitDs_ushort(GenTestParser::Ds_ushortContext * /*ctx*/) override { }

  virtual void enterDs_uchar(GenTestParser::Ds_ucharContext * /*ctx*/) override { }
  virtual void exitDs_uchar(GenTestParser::Ds_ucharContext * /*ctx*/) override { }

  virtual void enterDs_char(GenTestParser::Ds_charContext * /*ctx*/) override { }
  virtual void exitDs_char(GenTestParser::Ds_charContext * /*ctx*/) override { }

  virtual void enterDs_bool(GenTestParser::Ds_boolContext * /*ctx*/) override { }
  virtual void exitDs_bool(GenTestParser::Ds_boolContext * /*ctx*/) override { }

  virtual void enterDs_malloc(GenTestParser::Ds_mallocContext * /*ctx*/) override { }
  virtual void exitDs_malloc(GenTestParser::Ds_mallocContext * /*ctx*/) override { }

  virtual void enterDs_c_str(GenTestParser::Ds_c_strContext * /*ctx*/) override { }
  virtual void exitDs_c_str(GenTestParser::Ds_c_strContext * /*ctx*/) override { }

  virtual void enterDs_c_struptolen(GenTestParser::Ds_c_struptolenContext * /*ctx*/) override { }
  virtual void exitDs_c_struptolen(GenTestParser::Ds_c_struptolenContext * /*ctx*/) override { }

  virtual void enterTest(GenTestParser::TestContext * /*ctx*/) override { }
  virtual void exitTest(GenTestParser::TestContext * /*ctx*/) override { }

  virtual void enterSymbolic(GenTestParser::SymbolicContext * /*ctx*/) override { }
  virtual void exitSymbolic(GenTestParser::SymbolicContext * /*ctx*/) override { }

  virtual void enterSymbolic_underscore(GenTestParser::Symbolic_underscoreContext * /*ctx*/) override { }
  virtual void exitSymbolic_underscore(GenTestParser::Symbolic_underscoreContext * /*ctx*/) override { }

  virtual void enterSymbolic_bracket(GenTestParser::Symbolic_bracketContext * /*ctx*/) override { }
  virtual void exitSymbolic_bracket(GenTestParser::Symbolic_bracketContext * /*ctx*/) override { }

  virtual void enterText(GenTestParser::TextContext * /*ctx*/) override { }
  virtual void exitText(GenTestParser::TextContext * /*ctx*/) override { }


  virtual void enterEveryRule(antlr4::ParserRuleContext * /*ctx*/) override { }
  virtual void exitEveryRule(antlr4::ParserRuleContext * /*ctx*/) override { }
  virtual void visitTerminal(antlr4::tree::TerminalNode * /*node*/) override { }
  virtual void visitErrorNode(antlr4::tree::ErrorNode * /*node*/) override { }

};

