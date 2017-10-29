/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INCLUDE_MCTEST_MCUNIT_HPP_
#define INCLUDE_MCTEST_MCUNIT_HPP_

#include <mctest/McTest.hpp>

#include <sstream>

#define TEST(category, name) \
    McTest_EntryPoint(category ## _ ## name)

namespace mctest {

/* Base logger */
class Logger {
 public:
  MCTEST_INLINE Logger(McTest_LogLevel level_, bool expr_,
                       const char *file_, unsigned line_)
      : level(level_),
        expr(!!McTest_IsTrue(expr_)),
        file(file_),
        line(line_) {}

  MCTEST_INLINE ~Logger(void) {
    if (!expr) {
      std::stringstream report_ss;
      report_ss << file << "(" << line << "): " << ss.str();
      auto report_str = report_ss.str();
      auto report_c_str = report_str.c_str();
      McTest_Log(level, report_c_str, report_c_str + report_str.size());
    }
  }

  MCTEST_INLINE std::stringstream &stream(void) {
    return ss;
  }

 private:
  Logger(void) = delete;
  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;

  const McTest_LogLevel level;
  const bool expr;
  const char * const file;
  const unsigned line;
  std::stringstream ss;
};

}  // namespace mctest

#define MCTEST_LOG_BINOP(a, b, op, level) \
    ::mctest::Logger( \
        level, ((a) op (b)), __FILE__, __LINE__).stream()

#define ASSERT_EQ(a, b) MCTEST_LOG_BINOP(a, b, ==, McTest_LogFatal)
#define ASSERT_NE(a, b) MCTEST_LOG_BINOP(a, b, !=, McTest_LogFatal)
#define ASSERT_LT(a, b) MCTEST_LOG_BINOP(a, b, <, McTest_LogFatal)
#define ASSERT_LE(a, b) MCTEST_LOG_BINOP(a, b, <=, McTest_LogFatal)
#define ASSERT_GT(a, b) MCTEST_LOG_BINOP(a, b, >, McTest_LogFatal)
#define ASSERT_GE(a, b) MCTEST_LOG_BINOP(a, b, >=, McTest_LogFatal)

#define CHECK_EQ(a, b) MCTEST_LOG_BINOP(a, b, ==, McTest_LogError)
#define CHECK_NE(a, b) MCTEST_LOG_BINOP(a, b, !=, McTest_LogError)
#define CHECK_LT(a, b) MCTEST_LOG_BINOP(a, b, <, McTest_LogError)
#define CHECK_LE(a, b) MCTEST_LOG_BINOP(a, b, <=, McTest_LogError)
#define CHECK_GT(a, b) MCTEST_LOG_BINOP(a, b, >, McTest_LogError)
#define CHECK_GE(a, b) MCTEST_LOG_BINOP(a, b, >=, McTest_LogError)

#define ASSERT(expr) \
    ::mctest::Logger( \
        McTest_LogFatal, !!(expr), __FILE__, __LINE__).stream()

#define ASSERT_TRUE ASSERT
#define ASSERT_FALSE(expr) ASSERT(!(expr))

#define CHECK(expr) \
    ::mctest::Logger( \
        McTest_LogError, !!(expr), __FILE__, __LINE__).stream()

#define CHECK_TRUE CHECK
#define CHECK_FALSE(expr) CHECK(!(expr))

#define ASSUME(expr) \
    McTest_Assume(expr), ::mctest::Logger( \
        McTest_LogInfo, false, __FILE__, __LINE__).stream()


#define MCTEST_ASSUME_BINOP(a, b, op) \
    McTest_Assume(((a) op (b))), ::mctest::Logger( \
        McTest_LogInfo, false, __FILE__, __LINE__).stream()

#define ASSUME_EQ(a, b) MCTEST_ASSUME_BINOP(a, b, ==)
#define ASSUME_NE(a, b) MCTEST_ASSUME_BINOP(a, b, !=)
#define ASSUME_LT(a, b) MCTEST_ASSUME_BINOP(a, b, <)
#define ASSUME_LE(a, b) MCTEST_ASSUME_BINOP(a, b, <=)
#define ASSUME_GT(a, b) MCTEST_ASSUME_BINOP(a, b, >)
#define ASSUME_GE(a, b) MCTEST_ASSUME_BINOP(a, b, >=)

#endif  // INCLUDE_MCTEST_MCUNIT_HPP_
