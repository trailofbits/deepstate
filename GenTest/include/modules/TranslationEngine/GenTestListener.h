
// Generated from GenTest.g4 by ANTLR 4.8

#pragma once


#include "antlr4-runtime.h"
#include "GenTestParser.h"


/**
 * This interface defines an abstract listener for a parse tree produced by GenTestParser.
 */
class  GenTestListener : public antlr4::tree::ParseTreeListener {
public:

  virtual void enterFile(GenTestParser::FileContext *ctx) = 0;
  virtual void exitFile(GenTestParser::FileContext *ctx) = 0;

  virtual void enterLine(GenTestParser::LineContext *ctx) = 0;
  virtual void exitLine(GenTestParser::LineContext *ctx) = 0;

  virtual void enterType(GenTestParser::TypeContext *ctx) = 0;
  virtual void exitType(GenTestParser::TypeContext *ctx) = 0;

  virtual void enterTarget(GenTestParser::TargetContext *ctx) = 0;
  virtual void exitTarget(GenTestParser::TargetContext *ctx) = 0;

  virtual void enterComment(GenTestParser::CommentContext *ctx) = 0;
  virtual void exitComment(GenTestParser::CommentContext *ctx) = 0;

  virtual void enterLoop(GenTestParser::LoopContext *ctx) = 0;
  virtual void exitLoop(GenTestParser::LoopContext *ctx) = 0;

  virtual void enterFor_var(GenTestParser::For_varContext *ctx) = 0;
  virtual void exitFor_var(GenTestParser::For_varContext *ctx) = 0;

  virtual void enterFor_run(GenTestParser::For_runContext *ctx) = 0;
  virtual void exitFor_run(GenTestParser::For_runContext *ctx) = 0;

  virtual void enterFor_inc(GenTestParser::For_incContext *ctx) = 0;
  virtual void exitFor_inc(GenTestParser::For_incContext *ctx) = 0;

  virtual void enterInclude(GenTestParser::IncludeContext *ctx) = 0;
  virtual void exitInclude(GenTestParser::IncludeContext *ctx) = 0;

  virtual void enterType_definitions(GenTestParser::Type_definitionsContext *ctx) = 0;
  virtual void exitType_definitions(GenTestParser::Type_definitionsContext *ctx) = 0;

  virtual void enterStructure(GenTestParser::StructureContext *ctx) = 0;
  virtual void exitStructure(GenTestParser::StructureContext *ctx) = 0;

  virtual void enterNoinline(GenTestParser::NoinlineContext *ctx) = 0;
  virtual void exitNoinline(GenTestParser::NoinlineContext *ctx) = 0;

  virtual void enterDsinline(GenTestParser::DsinlineContext *ctx) = 0;
  virtual void exitDsinline(GenTestParser::DsinlineContext *ctx) = 0;

  virtual void enterDsnoreturn(GenTestParser::DsnoreturnContext *ctx) = 0;
  virtual void exitDsnoreturn(GenTestParser::DsnoreturnContext *ctx) = 0;

  virtual void enterAssume_gt(GenTestParser::Assume_gtContext *ctx) = 0;
  virtual void exitAssume_gt(GenTestParser::Assume_gtContext *ctx) = 0;

  virtual void enterAssume_lt(GenTestParser::Assume_ltContext *ctx) = 0;
  virtual void exitAssume_lt(GenTestParser::Assume_ltContext *ctx) = 0;

  virtual void enterAssume_ge(GenTestParser::Assume_geContext *ctx) = 0;
  virtual void exitAssume_ge(GenTestParser::Assume_geContext *ctx) = 0;

  virtual void enterAssume_le(GenTestParser::Assume_leContext *ctx) = 0;
  virtual void exitAssume_le(GenTestParser::Assume_leContext *ctx) = 0;

  virtual void enterAssume_eq(GenTestParser::Assume_eqContext *ctx) = 0;
  virtual void exitAssume_eq(GenTestParser::Assume_eqContext *ctx) = 0;

  virtual void enterAssume_ne(GenTestParser::Assume_neContext *ctx) = 0;
  virtual void exitAssume_ne(GenTestParser::Assume_neContext *ctx) = 0;

  virtual void enterAssrt(GenTestParser::AssrtContext *ctx) = 0;
  virtual void exitAssrt(GenTestParser::AssrtContext *ctx) = 0;

  virtual void enterAssert_gt(GenTestParser::Assert_gtContext *ctx) = 0;
  virtual void exitAssert_gt(GenTestParser::Assert_gtContext *ctx) = 0;

  virtual void enterAssert_lt(GenTestParser::Assert_ltContext *ctx) = 0;
  virtual void exitAssert_lt(GenTestParser::Assert_ltContext *ctx) = 0;

  virtual void enterAssert_ge(GenTestParser::Assert_geContext *ctx) = 0;
  virtual void exitAssert_ge(GenTestParser::Assert_geContext *ctx) = 0;

  virtual void enterAssert_le(GenTestParser::Assert_leContext *ctx) = 0;
  virtual void exitAssert_le(GenTestParser::Assert_leContext *ctx) = 0;

  virtual void enterAssert_eq(GenTestParser::Assert_eqContext *ctx) = 0;
  virtual void exitAssert_eq(GenTestParser::Assert_eqContext *ctx) = 0;

  virtual void enterAssert_ne(GenTestParser::Assert_neContext *ctx) = 0;
  virtual void exitAssert_ne(GenTestParser::Assert_neContext *ctx) = 0;

  virtual void enterCheck_gt(GenTestParser::Check_gtContext *ctx) = 0;
  virtual void exitCheck_gt(GenTestParser::Check_gtContext *ctx) = 0;

  virtual void enterCheck_lt(GenTestParser::Check_ltContext *ctx) = 0;
  virtual void exitCheck_lt(GenTestParser::Check_ltContext *ctx) = 0;

  virtual void enterCheck_ge(GenTestParser::Check_geContext *ctx) = 0;
  virtual void exitCheck_ge(GenTestParser::Check_geContext *ctx) = 0;

  virtual void enterCheck_le(GenTestParser::Check_leContext *ctx) = 0;
  virtual void exitCheck_le(GenTestParser::Check_leContext *ctx) = 0;

  virtual void enterCheck_eq(GenTestParser::Check_eqContext *ctx) = 0;
  virtual void exitCheck_eq(GenTestParser::Check_eqContext *ctx) = 0;

  virtual void enterCheck_ne(GenTestParser::Check_neContext *ctx) = 0;
  virtual void exitCheck_ne(GenTestParser::Check_neContext *ctx) = 0;

  virtual void enterDs_assume(GenTestParser::Ds_assumeContext *ctx) = 0;
  virtual void exitDs_assume(GenTestParser::Ds_assumeContext *ctx) = 0;

  virtual void enterDs_assert(GenTestParser::Ds_assertContext *ctx) = 0;
  virtual void exitDs_assert(GenTestParser::Ds_assertContext *ctx) = 0;

  virtual void enterDs_check(GenTestParser::Ds_checkContext *ctx) = 0;
  virtual void exitDs_check(GenTestParser::Ds_checkContext *ctx) = 0;

  virtual void enterDs_int(GenTestParser::Ds_intContext *ctx) = 0;
  virtual void exitDs_int(GenTestParser::Ds_intContext *ctx) = 0;

  virtual void enterDs_uint8(GenTestParser::Ds_uint8Context *ctx) = 0;
  virtual void exitDs_uint8(GenTestParser::Ds_uint8Context *ctx) = 0;

  virtual void enterDs_uint16(GenTestParser::Ds_uint16Context *ctx) = 0;
  virtual void exitDs_uint16(GenTestParser::Ds_uint16Context *ctx) = 0;

  virtual void enterDs_uint32(GenTestParser::Ds_uint32Context *ctx) = 0;
  virtual void exitDs_uint32(GenTestParser::Ds_uint32Context *ctx) = 0;

  virtual void enterDs_uint64(GenTestParser::Ds_uint64Context *ctx) = 0;
  virtual void exitDs_uint64(GenTestParser::Ds_uint64Context *ctx) = 0;

  virtual void enterDs_float(GenTestParser::Ds_floatContext *ctx) = 0;
  virtual void exitDs_float(GenTestParser::Ds_floatContext *ctx) = 0;

  virtual void enterDs_double(GenTestParser::Ds_doubleContext *ctx) = 0;
  virtual void exitDs_double(GenTestParser::Ds_doubleContext *ctx) = 0;

  virtual void enterDs_ushort(GenTestParser::Ds_ushortContext *ctx) = 0;
  virtual void exitDs_ushort(GenTestParser::Ds_ushortContext *ctx) = 0;

  virtual void enterDs_uchar(GenTestParser::Ds_ucharContext *ctx) = 0;
  virtual void exitDs_uchar(GenTestParser::Ds_ucharContext *ctx) = 0;

  virtual void enterDs_char(GenTestParser::Ds_charContext *ctx) = 0;
  virtual void exitDs_char(GenTestParser::Ds_charContext *ctx) = 0;

  virtual void enterDs_malloc(GenTestParser::Ds_mallocContext *ctx) = 0;
  virtual void exitDs_malloc(GenTestParser::Ds_mallocContext *ctx) = 0;

  virtual void enterDs_c_str(GenTestParser::Ds_c_strContext *ctx) = 0;
  virtual void exitDs_c_str(GenTestParser::Ds_c_strContext *ctx) = 0;

  virtual void enterDs_c_struptolen(GenTestParser::Ds_c_struptolenContext *ctx) = 0;
  virtual void exitDs_c_struptolen(GenTestParser::Ds_c_struptolenContext *ctx) = 0;

  virtual void enterTest(GenTestParser::TestContext *ctx) = 0;
  virtual void exitTest(GenTestParser::TestContext *ctx) = 0;

  virtual void enterSymbolic(GenTestParser::SymbolicContext *ctx) = 0;
  virtual void exitSymbolic(GenTestParser::SymbolicContext *ctx) = 0;

  virtual void enterSymbolic_underscore(GenTestParser::Symbolic_underscoreContext *ctx) = 0;
  virtual void exitSymbolic_underscore(GenTestParser::Symbolic_underscoreContext *ctx) = 0;

  virtual void enterSymbolic_bracket(GenTestParser::Symbolic_bracketContext *ctx) = 0;
  virtual void exitSymbolic_bracket(GenTestParser::Symbolic_bracketContext *ctx) = 0;

  virtual void enterText(GenTestParser::TextContext *ctx) = 0;
  virtual void exitText(GenTestParser::TextContext *ctx) = 0;


};

