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

#ifndef SRC_INCLUDE_MCTEST_MCUNIT_HPP_
#define SRC_INCLUDE_MCTEST_MCUNIT_HPP_

#include <mctest/McTest.hpp>
#include <mctest/Stream.hpp>

#define TEST(category, name) \
    McTest_EntryPoint(category ## _ ## name)

#define LOG_DEBUG(cond) \
    ::mctest::Stream(McTest_LogDebug, (cond), __FILE__, __LINE__)

#define LOG_INFO(cond) \
    ::mctest::Stream(McTest_LogInfo, (cond), __FILE__, __LINE__)

#define LOG_WARNING(cond) \
    ::mctest::Stream(McTest_LogWarning, (cond), __FILE__, __LINE__)

#define LOG_WARN(cond) \
    ::mctest::Stream(McTest_LogWarning, (cond), __FILE__, __LINE__)

#define LOG_ERROR(cond) \
    ::mctest::Stream(McTest_LogError, (cond), __FILE__, __LINE__)

#define LOG_FATAL(cond) \
    ::mctest::Stream(McTest_LogFatal, (cond), __FILE__, __LINE__)

#define LOG_CRITICAl(cond) \
    ::mctest::Stream(McTest_LogFatal, (cond), __FILE__, __LINE__)

#define LOG(LEVEL) LOG_ ## LEVEL(true)

#define LOG_IF(LEVEL, cond) LOG_ ## LEVEL(cond)


#define MCTEST_LOG_BINOP(a, b, op, level) \
    ::mctest::Stream( \
        level, !((a) op (b)), __FILE__, __LINE__)

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
    ::mctest::Stream( \
        McTest_LogFatal, !(expr), __FILE__, __LINE__)

#define ASSERT_TRUE ASSERT
#define ASSERT_FALSE(expr) ASSERT(!(expr))

#define CHECK(expr) \
    ::mctest::Stream( \
        McTest_LogError, !(expr), __FILE__, __LINE__)

#define CHECK_TRUE CHECK
#define CHECK_FALSE(expr) CHECK(!(expr))

#define ASSUME(expr) \
    McTest_Assume(expr), ::mctest::Stream( \
        McTest_LogInfo, true, __FILE__, __LINE__)

#define MCTEST_ASSUME_BINOP(a, b, op) \
    McTest_Assume(((a) op (b))), ::mctest::Stream( \
        McTest_LogInfo, true, __FILE__, __LINE__)

#define ASSUME_EQ(a, b) MCTEST_ASSUME_BINOP(a, b, ==)
#define ASSUME_NE(a, b) MCTEST_ASSUME_BINOP(a, b, !=)
#define ASSUME_LT(a, b) MCTEST_ASSUME_BINOP(a, b, <)
#define ASSUME_LE(a, b) MCTEST_ASSUME_BINOP(a, b, <=)
#define ASSUME_GT(a, b) MCTEST_ASSUME_BINOP(a, b, >)
#define ASSUME_GE(a, b) MCTEST_ASSUME_BINOP(a, b, >=)

#endif  // SRC_INCLUDE_MCTEST_MCUNIT_HPP_
