
// Generated from GenTest.g4 by ANTLR 4.8

#pragma once


#include "antlr4-runtime.h"




class  GenTestParser : public antlr4::Parser {
public:
  enum {
    T__0 = 1, T__1 = 2, T__2 = 3, T__3 = 4, T__4 = 5, T__5 = 6, T__6 = 7, 
    T__7 = 8, T__8 = 9, T__9 = 10, T__10 = 11, T__11 = 12, T__12 = 13, T__13 = 14, 
    T__14 = 15, T__15 = 16, T__16 = 17, T__17 = 18, T__18 = 19, T__19 = 20, 
    T__20 = 21, T__21 = 22, T__22 = 23, T__23 = 24, T__24 = 25, T__25 = 26, 
    T__26 = 27, T__27 = 28, T__28 = 29, T__29 = 30, T__30 = 31, T__31 = 32, 
    T__32 = 33, T__33 = 34, T__34 = 35, T__35 = 36, T__36 = 37, T__37 = 38, 
    T__38 = 39, T__39 = 40, T__40 = 41, T__41 = 42, T__42 = 43, T__43 = 44, 
    T__44 = 45, T__45 = 46, T__46 = 47, T__47 = 48, T__48 = 49, T__49 = 50, 
    ASSUME_C = 51, ASSUME = 52, ASSRT = 53, ASSRT_C = 54, DEEPSTATE = 55, 
    CHK = 56, CHK_C = 57, GREATER = 58, LESS = 59, GREATER_EQ = 60, LESS_EQ = 61, 
    EQ = 62, NOT_E = 63, TEST = 64, DEEPSTATE_INLINE = 65, DEEPSTATE_NOINLINE = 66, 
    DEEPSTATE_NORETURN = 67, SYMBOLIC = 68, SYMBOLIC_C = 69, FORALL = 70, 
    INT = 71, UINT8 = 72, UINT16 = 73, UINT32 = 74, UINT64 = 75, SHORT = 76, 
    LONG = 77, DOUBLE = 78, FLOAT = 79, CHAR = 80, UNSIGNED = 81, BOOL = 82, 
    IDENTIFIER = 83, NUM = 84, WS = 85, NEWLINE = 86, TAB = 87, SEMICOLON = 88, 
    TRUE = 89, FALSE = 90
  };

  enum {
    RuleFile = 0, RuleLine = 1, RuleType = 2, RuleTarget = 3, RuleComment = 4, 
    RuleLoop = 5, RuleFor_var = 6, RuleFor_run = 7, RuleFor_inc = 8, RuleInclude = 9, 
    RuleType_definitions = 10, RuleStructure = 11, RuleNoinline = 12, RuleDsinline = 13, 
    RuleDsnoreturn = 14, RuleAssume_gt = 15, RuleAssume_lt = 16, RuleAssume_ge = 17, 
    RuleAssume_le = 18, RuleAssume_eq = 19, RuleAssume_ne = 20, RuleAssrt = 21, 
    RuleAssert_gt = 22, RuleAssert_lt = 23, RuleAssert_ge = 24, RuleAssert_le = 25, 
    RuleAssert_eq = 26, RuleAssert_ne = 27, RuleCheck_gt = 28, RuleCheck_lt = 29, 
    RuleCheck_ge = 30, RuleCheck_le = 31, RuleCheck_eq = 32, RuleCheck_ne = 33, 
    RuleDs_assume = 34, RuleDs_assert = 35, RuleDs_check = 36, RuleDs_int = 37, 
    RuleDs_uint8 = 38, RuleDs_uint16 = 39, RuleDs_uint32 = 40, RuleDs_uint64 = 41, 
    RuleDs_float = 42, RuleDs_double = 43, RuleDs_ushort = 44, RuleDs_uchar = 45, 
    RuleDs_char = 46, RuleDs_malloc = 47, RuleDs_c_str = 48, RuleDs_c_struptolen = 49, 
    RuleTest = 50, RuleSymbolic = 51, RuleSymbolic_underscore = 52, RuleSymbolic_bracket = 53, 
    RuleText = 54
  };

  GenTestParser(antlr4::TokenStream *input);
  ~GenTestParser();

  virtual std::string getGrammarFileName() const override;
  virtual const antlr4::atn::ATN& getATN() const override { return _atn; };
  virtual const std::vector<std::string>& getTokenNames() const override { return _tokenNames; }; // deprecated: use vocabulary instead.
  virtual const std::vector<std::string>& getRuleNames() const override;
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;


  class FileContext;
  class LineContext;
  class TypeContext;
  class TargetContext;
  class CommentContext;
  class LoopContext;
  class For_varContext;
  class For_runContext;
  class For_incContext;
  class IncludeContext;
  class Type_definitionsContext;
  class StructureContext;
  class NoinlineContext;
  class DsinlineContext;
  class DsnoreturnContext;
  class Assume_gtContext;
  class Assume_ltContext;
  class Assume_geContext;
  class Assume_leContext;
  class Assume_eqContext;
  class Assume_neContext;
  class AssrtContext;
  class Assert_gtContext;
  class Assert_ltContext;
  class Assert_geContext;
  class Assert_leContext;
  class Assert_eqContext;
  class Assert_neContext;
  class Check_gtContext;
  class Check_ltContext;
  class Check_geContext;
  class Check_leContext;
  class Check_eqContext;
  class Check_neContext;
  class Ds_assumeContext;
  class Ds_assertContext;
  class Ds_checkContext;
  class Ds_intContext;
  class Ds_uint8Context;
  class Ds_uint16Context;
  class Ds_uint32Context;
  class Ds_uint64Context;
  class Ds_floatContext;
  class Ds_doubleContext;
  class Ds_ushortContext;
  class Ds_ucharContext;
  class Ds_charContext;
  class Ds_mallocContext;
  class Ds_c_strContext;
  class Ds_c_struptolenContext;
  class TestContext;
  class SymbolicContext;
  class Symbolic_underscoreContext;
  class Symbolic_bracketContext;
  class TextContext; 

  class  FileContext : public antlr4::ParserRuleContext {
  public:
    FileContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EOF();
    std::vector<LineContext *> line();
    LineContext* line(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<IncludeContext *> include();
    IncludeContext* include(size_t i);
    std::vector<Type_definitionsContext *> type_definitions();
    Type_definitionsContext* type_definitions(size_t i);
    std::vector<StructureContext *> structure();
    StructureContext* structure(size_t i);

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  FileContext* file();

  class  LineContext : public antlr4::ParserRuleContext {
  public:
    LineContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<TextContext *> text();
    TextContext* text(size_t i);
    std::vector<TargetContext *> target();
    TargetContext* target(size_t i);
    std::vector<CommentContext *> comment();
    CommentContext* comment(size_t i);
    antlr4::tree::TerminalNode *NEWLINE();
    antlr4::tree::TerminalNode *WS();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  LineContext* line();

  class  TypeContext : public antlr4::ParserRuleContext {
  public:
    TypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *INT();
    antlr4::tree::TerminalNode *BOOL();
    antlr4::tree::TerminalNode *UINT8();
    antlr4::tree::TerminalNode *UINT16();
    antlr4::tree::TerminalNode *UINT32();
    antlr4::tree::TerminalNode *UINT64();
    antlr4::tree::TerminalNode *SHORT();
    antlr4::tree::TerminalNode *LONG();
    antlr4::tree::TerminalNode *DOUBLE();
    antlr4::tree::TerminalNode *FLOAT();
    antlr4::tree::TerminalNode *CHAR();
    antlr4::tree::TerminalNode *UNSIGNED();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  TypeContext* type();

  class  TargetContext : public antlr4::ParserRuleContext {
  public:
    TargetContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    NoinlineContext *noinline();
    DsinlineContext *dsinline();
    DsnoreturnContext *dsnoreturn();
    Assume_gtContext *assume_gt();
    Assume_ltContext *assume_lt();
    Assume_geContext *assume_ge();
    Assume_leContext *assume_le();
    Assume_eqContext *assume_eq();
    Assume_neContext *assume_ne();
    AssrtContext *assrt();
    Assert_gtContext *assert_gt();
    Assert_ltContext *assert_lt();
    Assert_leContext *assert_le();
    Assert_geContext *assert_ge();
    Assert_eqContext *assert_eq();
    Assert_neContext *assert_ne();
    Check_gtContext *check_gt();
    Check_ltContext *check_lt();
    Check_geContext *check_ge();
    Check_leContext *check_le();
    Check_eqContext *check_eq();
    Check_neContext *check_ne();
    Ds_assumeContext *ds_assume();
    Ds_assertContext *ds_assert();
    Ds_checkContext *ds_check();
    TestContext *test();
    SymbolicContext *symbolic();
    Ds_intContext *ds_int();
    Ds_uint8Context *ds_uint8();
    Ds_uint16Context *ds_uint16();
    Ds_uint32Context *ds_uint32();
    Ds_uint64Context *ds_uint64();
    Ds_floatContext *ds_float();
    Ds_doubleContext *ds_double();
    Ds_ucharContext *ds_uchar();
    Ds_charContext *ds_char();
    Ds_ushortContext *ds_ushort();
    Ds_mallocContext *ds_malloc();
    Ds_c_strContext *ds_c_str();
    Ds_c_struptolenContext *ds_c_struptolen();
    LoopContext *loop();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  TargetContext* target();

  class  CommentContext : public antlr4::ParserRuleContext {
  public:
    CommentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<TextContext *> text();
    TextContext* text(size_t i);

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  CommentContext* comment();

  class  LoopContext : public antlr4::ParserRuleContext {
  public:
    LoopContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    For_varContext *for_var();
    std::vector<antlr4::tree::TerminalNode *> SEMICOLON();
    antlr4::tree::TerminalNode* SEMICOLON(size_t i);
    For_runContext *for_run();
    For_incContext *for_inc();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  LoopContext* loop();

  class  For_varContext : public antlr4::ParserRuleContext {
  public:
    For_varContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  For_varContext* for_var();

  class  For_runContext : public antlr4::ParserRuleContext {
  public:
    For_runContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  For_runContext* for_run();

  class  For_incContext : public antlr4::ParserRuleContext {
  public:
    For_incContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  For_incContext* for_inc();

  class  IncludeContext : public antlr4::ParserRuleContext {
  public:
    IncludeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *NEWLINE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  IncludeContext* include();

  class  Type_definitionsContext : public antlr4::ParserRuleContext {
  public:
    Type_definitionsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    StructureContext *structure();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Type_definitionsContext* type_definitions();

  class  StructureContext : public antlr4::ParserRuleContext {
  public:
    StructureContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  StructureContext* structure();

  class  NoinlineContext : public antlr4::ParserRuleContext {
  public:
    NoinlineContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DEEPSTATE_NOINLINE();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  NoinlineContext* noinline();

  class  DsinlineContext : public antlr4::ParserRuleContext {
  public:
    DsinlineContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DEEPSTATE_INLINE();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  DsinlineContext* dsinline();

  class  DsnoreturnContext : public antlr4::ParserRuleContext {
  public:
    DsnoreturnContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DEEPSTATE_NORETURN();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  DsnoreturnContext* dsnoreturn();

  class  Assume_gtContext : public antlr4::ParserRuleContext {
  public:
    Assume_gtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *GREATER();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_gtContext* assume_gt();

  class  Assume_ltContext : public antlr4::ParserRuleContext {
  public:
    Assume_ltContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *LESS();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_ltContext* assume_lt();

  class  Assume_geContext : public antlr4::ParserRuleContext {
  public:
    Assume_geContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *GREATER_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_geContext* assume_ge();

  class  Assume_leContext : public antlr4::ParserRuleContext {
  public:
    Assume_leContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *LESS_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_leContext* assume_le();

  class  Assume_eqContext : public antlr4::ParserRuleContext {
  public:
    Assume_eqContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_eqContext* assume_eq();

  class  Assume_neContext : public antlr4::ParserRuleContext {
  public:
    Assume_neContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME_C();
    antlr4::tree::TerminalNode *NOT_E();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assume_neContext* assume_ne();

  class  AssrtContext : public antlr4::ParserRuleContext {
  public:
    AssrtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    std::vector<TextContext *> text();
    TextContext* text(size_t i);

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  AssrtContext* assrt();

  class  Assert_gtContext : public antlr4::ParserRuleContext {
  public:
    Assert_gtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *GREATER();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_gtContext* assert_gt();

  class  Assert_ltContext : public antlr4::ParserRuleContext {
  public:
    Assert_ltContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *LESS();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_ltContext* assert_lt();

  class  Assert_geContext : public antlr4::ParserRuleContext {
  public:
    Assert_geContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *GREATER_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_geContext* assert_ge();

  class  Assert_leContext : public antlr4::ParserRuleContext {
  public:
    Assert_leContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *LESS_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_leContext* assert_le();

  class  Assert_eqContext : public antlr4::ParserRuleContext {
  public:
    Assert_eqContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_eqContext* assert_eq();

  class  Assert_neContext : public antlr4::ParserRuleContext {
  public:
    Assert_neContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT_C();
    antlr4::tree::TerminalNode *NOT_E();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Assert_neContext* assert_ne();

  class  Check_gtContext : public antlr4::ParserRuleContext {
  public:
    Check_gtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *GREATER();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_gtContext* check_gt();

  class  Check_ltContext : public antlr4::ParserRuleContext {
  public:
    Check_ltContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *LESS();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_ltContext* check_lt();

  class  Check_geContext : public antlr4::ParserRuleContext {
  public:
    Check_geContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *GREATER_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_geContext* check_ge();

  class  Check_leContext : public antlr4::ParserRuleContext {
  public:
    Check_leContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *LESS_EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_leContext* check_le();

  class  Check_eqContext : public antlr4::ParserRuleContext {
  public:
    Check_eqContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *EQ();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_eqContext* check_eq();

  class  Check_neContext : public antlr4::ParserRuleContext {
  public:
    Check_neContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHK_C();
    antlr4::tree::TerminalNode *NOT_E();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Check_neContext* check_ne();

  class  Ds_assumeContext : public antlr4::ParserRuleContext {
  public:
    Ds_assumeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSUME();
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_assumeContext* ds_assume();

  class  Ds_assertContext : public antlr4::ParserRuleContext {
  public:
    Ds_assertContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT();
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_assertContext* ds_assert();

  class  Ds_checkContext : public antlr4::ParserRuleContext {
  public:
    Ds_checkContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ASSRT();
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_checkContext* ds_check();

  class  Ds_intContext : public antlr4::ParserRuleContext {
  public:
    Ds_intContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_intContext* ds_int();

  class  Ds_uint8Context : public antlr4::ParserRuleContext {
  public:
    Ds_uint8Context(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_uint8Context* ds_uint8();

  class  Ds_uint16Context : public antlr4::ParserRuleContext {
  public:
    Ds_uint16Context(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_uint16Context* ds_uint16();

  class  Ds_uint32Context : public antlr4::ParserRuleContext {
  public:
    Ds_uint32Context(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_uint32Context* ds_uint32();

  class  Ds_uint64Context : public antlr4::ParserRuleContext {
  public:
    Ds_uint64Context(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_uint64Context* ds_uint64();

  class  Ds_floatContext : public antlr4::ParserRuleContext {
  public:
    Ds_floatContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_floatContext* ds_float();

  class  Ds_doubleContext : public antlr4::ParserRuleContext {
  public:
    Ds_doubleContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_doubleContext* ds_double();

  class  Ds_ushortContext : public antlr4::ParserRuleContext {
  public:
    Ds_ushortContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_ushortContext* ds_ushort();

  class  Ds_ucharContext : public antlr4::ParserRuleContext {
  public:
    Ds_ucharContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_ucharContext* ds_uchar();

  class  Ds_charContext : public antlr4::ParserRuleContext {
  public:
    Ds_charContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_charContext* ds_char();

  class  Ds_mallocContext : public antlr4::ParserRuleContext {
  public:
    Ds_mallocContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_mallocContext* ds_malloc();

  class  Ds_c_strContext : public antlr4::ParserRuleContext {
  public:
    Ds_c_strContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_c_strContext* ds_c_str();

  class  Ds_c_struptolenContext : public antlr4::ParserRuleContext {
  public:
    Ds_c_struptolenContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TextContext *text();
    antlr4::tree::TerminalNode *DEEPSTATE();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Ds_c_struptolenContext* ds_c_struptolen();

  class  TestContext : public antlr4::ParserRuleContext {
  public:
    TestContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *TEST();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  TestContext* test();

  class  SymbolicContext : public antlr4::ParserRuleContext {
  public:
    SymbolicContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    Symbolic_underscoreContext *symbolic_underscore();
    Symbolic_bracketContext *symbolic_bracket();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  SymbolicContext* symbolic();

  class  Symbolic_underscoreContext : public antlr4::ParserRuleContext {
  public:
    Symbolic_underscoreContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SYMBOLIC();
    TypeContext *type();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Symbolic_underscoreContext* symbolic_underscore();

  class  Symbolic_bracketContext : public antlr4::ParserRuleContext {
  public:
    Symbolic_bracketContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SYMBOLIC_C();
    TypeContext *type();
    TextContext *text();

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  Symbolic_bracketContext* symbolic_bracket();

  class  TextContext : public antlr4::ParserRuleContext {
  public:
    TextContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> IDENTIFIER();
    antlr4::tree::TerminalNode* IDENTIFIER(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NUM();
    antlr4::tree::TerminalNode* NUM(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<antlr4::tree::TerminalNode *> SEMICOLON();
    antlr4::tree::TerminalNode* SEMICOLON(size_t i);
    std::vector<TypeContext *> type();
    TypeContext* type(size_t i);
    std::vector<antlr4::tree::TerminalNode *> DEEPSTATE();
    antlr4::tree::TerminalNode* DEEPSTATE(size_t i);
    std::vector<antlr4::tree::TerminalNode *> FORALL();
    antlr4::tree::TerminalNode* FORALL(size_t i);

    virtual void enterRule(antlr4::tree::ParseTreeListener *listener) override;
    virtual void exitRule(antlr4::tree::ParseTreeListener *listener) override;
   
  };

  TextContext* text();


private:
  static std::vector<antlr4::dfa::DFA> _decisionToDFA;
  static antlr4::atn::PredictionContextCache _sharedContextCache;
  static std::vector<std::string> _ruleNames;
  static std::vector<std::string> _tokenNames;

  static std::vector<std::string> _literalNames;
  static std::vector<std::string> _symbolicNames;
  static antlr4::dfa::Vocabulary _vocabulary;
  static antlr4::atn::ATN _atn;
  static std::vector<uint16_t> _serializedATN;


  struct Initializer {
    Initializer();
  };
  static Initializer _init;
};

