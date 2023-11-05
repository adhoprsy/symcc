#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
int main(int argc, char* argv[]) {
    int x;
    if (read(STDIN_FILENO, &x, sizeof(x)) != sizeof(x)) {
        printf("Failed to read x\n");
        return -1;
    }
    if (x < 100 && x > 10) { 
	    printf("1111111111111\n");
	}
    else 
	    printf("3333333333333\n");
    return 0;
}
