#include <stdio.h>
#include <locale.h>

int main() {
    char* result = setlocale(LC_TIME, NULL);
    result = setlocale(LC_TIME, "en_US.UTF-8");
    if(result == NULL) {
        printf("Failed to set locale");
        return 1;
    }
    printf("%s\n", result);
    return 0;
}
