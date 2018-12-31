#include <deepstate/DeepState.hpp>

using namespace deepstate;

char* encode(const char* input) {
  unsigned int l = strlen(input);
  char* encoded = (char*)malloc((l*2)+1);
  if (l == 0) {
    encoded[0] = '\0';
    return encoded;
  }
  unsigned char last = input[0];
  unsigned char current;
  int count = 1;
  int pos = 0;
  for (int i = 1; i < l; i++) {
    current = input[i];
    if ((current == last) && (count < 26)) {
      count++;
    } else {
      encoded[pos++] = last;
      encoded[pos++] = 64 + count;
      last = current;
      count = 1;
    }
  }
  encoded[pos++] = last;
  encoded[pos++] = 64 + count;
  encoded[pos] = '\0';
  return encoded;
}

char* decode(const char* output) {
  unsigned int l = strlen(output);
  char* decoded = (char*)malloc(((l/2)*25)+1);
  if (l == 0) {
    decoded[0] = '\0';
    return decoded;
  }
  int pos = 0;
  unsigned char current;
  for (int i = 0; i < l; i++) {
    current = output[i++];
    unsigned int count = output[i] - 64;
    for (int j = 0; j < count; j++) {
      decoded[pos++] = current;
    }
  }
  decoded[pos] = '\0';
  return decoded;
}

#define MAX_STR_LEN 100

TEST(Runlength, EncodeDecode) {
  char* original = DeepState_CStrUpToLen(MAX_STR_LEN, "abcde");
  LOG(TRACE) << "original = `" << original << "`";
  char* encoded = encode(original);
  char* roundtrip = decode(encoded);
  ASSERT (strncmp(roundtrip, original, MAX_STR_LEN) == 0) <<
    "encode = `" << encoded << "`, decode(encode) = `" << roundtrip << "`";
}
