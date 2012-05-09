#include <stdint.h>
#include <stdio.h>

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
(byte & 0x80 ? 1 : 0), \
(byte & 0x40 ? 1 : 0), \
(byte & 0x20 ? 1 : 0), \
(byte & 0x10 ? 1 : 0), \
(byte & 0x08 ? 1 : 0), \
(byte & 0x04 ? 1 : 0), \
(byte & 0x02 ? 1 : 0), \
(byte & 0x01 ? 1 : 0) 


int main(int argc, char * argv[]) {
  int i;

  printf("static const char * dump_binary_string_map[] = {");
  for(i = 0; i < 255; ++i) {
    printf("  \"" BYTETOBINARYPATTERN "\",\n", BYTETOBINARY(i));
  }
  printf("  \"" BYTETOBINARYPATTERN "\"\n};\n\n", BYTETOBINARY(i));

  printf("static const char * dump_hex_string_map[] = {");
  for(i = 0; i < 255; ++i) {
    printf("  \"%02x\",\n", i);
  }
  printf("  \"%02x\"\n};\n\n", 255);

  return 0;
}
