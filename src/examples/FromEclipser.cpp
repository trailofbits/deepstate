#include <deepstate/DeepState.hpp>

using namespace deepstate;

#include <assert.h>

int vulnfunc(int32_t intInput, char * strInput) {
   if (2 * intInput + 1 == 31337)
      if (strcmp(strInput, "Bad!") == 0)
         assert(0);
   return 0;
}

TEST(FromEclipser, CrashIt) {
   char *buf = (char*)DeepState_Malloc(9);
   buf[8] = 0;
   vulnfunc(*((int32_t*) &buf[0]), &buf[4]);
   free(buf);
}
