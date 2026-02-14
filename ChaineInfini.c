#include "ChaineInfinie.h"

char *input() {
    char *str = malloc(2);
    str[1] = 0;
    char buf[2];

    int compteur = 4;
    while (str[strlen(str) - 1] != '\n') {
        fgets(buf, 2, stdin);

        str = realloc(str, compteur);
        if (str == NULL) {
            free(str);
            puts("input() - realloc a crashé !");
            return NULL;
        }

        strcat(str, buf);
        compteur += 2;
    }

    return str;
}

/*int main()
{
    char *str = input();
    printf("%s", str);

    free(str);
    return 0;
}*/
