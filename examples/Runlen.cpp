#include <deepstate/DeepState.hpp>

using namespace deepstate;

/* Simple, buggy, run-length encoding that creates "human readable"
 * encodings by adding 'A'-1 to the count, and splitting at 26 */

char* encode(const char* input) {
  char* encoded = (char*)malloc((strlen(input)*2)+1);
  int pos = 0;
  if (strlen(input) > 0) {
    unsigned char last = input[0]; int count = 1;
    for (int i = 1; i < strlen(input); i++) {
      if (((unsigned char)input[i] == last) && (count < 26))
	count++;
      else {
	encoded[pos++] = last; encoded[pos++] = 64 + count;
	last = (unsigned char)input[i]; count = 1;
      }
    }
    encoded[pos++] = last; encoded[pos++] = 65; // Should be 64 + count
  }
  encoded[pos] = '\0';
  return encoded;
}

char* decode(const char* output) {
  char* decoded = (char*)malloc(((strlen(output))/2)*26);
  int pos = 0;
  if (strlen(output) > 0) {
    for (int i = 0; i < strlen(output); i += 2)
      for (int j = 0; j < (output[i+1] - 64); j++)
	decoded[pos++] = output[i];
  }
  decoded[pos] = '\0';
  return decoded;
}

// Can be (much) higher (e.g., > 1024) if we're using fuzzing, not symbolic execution
#define MAX_STR_LEN 2

TEST(Runlength, EncodeDecode) {
  char* original = DeepState_CStrUpToLen(MAX_STR_LEN, "ab");
  char* encoded = encode(original);
  char* roundtrip = decode(encoded);
  ASSERT (strncmp(roundtrip, original, MAX_STR_LEN) == 0) <<
    "`" << original << "` ==> `" << encoded << "` ==> `" << roundtrip << "`";
}
