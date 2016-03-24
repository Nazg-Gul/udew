#include <stdlib.h>
#include <stdio.h>
#include "udew.h"

int main(int argc, char* argv[]) {
  if (udewInit() == UDEW_SUCCESS) {
    printf("UDEV found\n");
  }
  else {
    printf("UDEV not found\n");
  }
  return EXIT_SUCCESS;
}
