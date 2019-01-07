#include <stdio.h>
#include <stdlib.h>

int square(int x) {
  return x*x;
}

#ifdef DEEPSTATE_TEST
#include <deepstate/DeepState.h>
DeepState_EntryPoint(test_main) {
  const char *new_args[2];
  new_args[0] = "deepstate";
  new_args[1] = DeepState_CStr_C(8, 0);

  DeepState_Assert(0 == old_main(2, new_args));
}

int main(int argc, const char *argv[]) {
  DeepState_InitOptions(argc, argv);
  return 0 == DeepState_Run();
}
// TODO(artem): yes this is awful but avoids another `ifdef`.
#define main old_main

#endif

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <integer>\n", argv[0]);
    return -1;
  }
  int x = atoi(argv[1]);
  int y = square(x);

  if (y + 4 == 29) {
    printf("You found the secret number\n");
    return 0;
  } else {
    printf("Secret NOT found\n");
    return -1;
  }
}
