#include "chacha20-c/chacha20.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void generer_nonce(uint8_t nonce[12]) {
    /*int fd = open("/dev/urandom", O_RDONLY);
    read(fd, nonce, 12);
    close(fd);*/

    FILE *f = fopen("nonce.crypt", "r");
    if (f != NULL) {
        uint8_t data[50];
        while (fgets((char *)data, 50, f) != NULL) {

            // Print the data
            // printf("Nonce : %s\n", data);
            strcpy((char *)nonce, (char *)data);
        }
        fclose(f);
    }
}

void generer_cle(uint8_t cle[32]) {
    /*int fd = open("/dev/urandom", O_RDONLY);
    read(fd, cle, 32);
    close(fd);*/

    FILE *f = fopen("cle.crypt", "r");
    if (f != NULL) {
        uint8_t data[50];
        while (fgets((char *)data, 50, f) != NULL) {

            // Print the data
            // printf("Clé : %s\n", data);
            strcat((char *)cle, (char *)data);
        }
    }
    fclose(f);
}

void convertir_msg(uint8_t *msg_en_nombres, char *msg) {
    const uint len_msg = strlen(msg);
    for (uint i = 0; i < len_msg; ++i) {
        msg_en_nombres[i] = (uint8_t)msg[i];
    }
}

void recevoir_messages(int serveur_socket) {
    char buffer[BUFFER_SIZE];
    uint8_t msg_dechiffre[BUFFER_SIZE];
    ssize_t bytes;

    struct chacha20_context ctx;

    uint8_t nonce[12];
    uint8_t cle[32];

    generer_nonce(nonce);
    generer_cle(cle);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        memset(msg_dechiffre, 0, BUFFER_SIZE);

        bytes = read(serveur_socket, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) {
            printf("Serveur déconnecté\n");
            break;
        }

        buffer[bytes] = '\0';

        // convertir_msg(msg_dechiffre, buffer);
        memcpy(msg_dechiffre, buffer, strlen(buffer));

        chacha20_init_context(&ctx, cle, nonce, 0);
        chacha20_xor(&ctx, msg_dechiffre, strlen(buffer));

        // if (strcmp((char *)buffer, "exit") == 0) {
        if (strcmp((char *)msg_dechiffre, "exit") == 0) {
            printf("Serveur a quitté\n");
            break;
        }
        printf("Serveur : %s\n", msg_dechiffre);
        // printf("Serveur : %s\n", buffer);
    }
}

void *envoyer_messages(void *arg) {
    int sock = *(int *)arg;
    char msg[BUFFER_SIZE];

    struct chacha20_context ctx;

    uint8_t nonce[12];
    uint8_t cle[32];

    generer_nonce(nonce);
    generer_cle(cle);

    while (1) {
        memset(msg, 0, BUFFER_SIZE);

        if (fgets(msg, BUFFER_SIZE, stdin) == NULL)
            break;

        size_t len = strlen(msg);
        if (len > 0 && msg[len - 1] == '\n')
            msg[len - 1] = '\0';

        uint8_t *msg_en_nombres =
            (uint8_t *)malloc(strlen(msg) * sizeof(uint8_t));
        // convertir_msg(msg_en_nombres, msg);
        memcpy(msg_en_nombres, msg, strlen(msg));

        chacha20_init_context(&ctx, cle, nonce, 0);
        chacha20_xor(&ctx, msg_en_nombres, strlen(msg));

        printf("Vous : %s\n", msg);

        if (strcmp(msg, "exit") == 0) {
            // send(sock, msg, strlen(msg), 0);
            send(sock, msg_en_nombres, strlen(msg), 0);
            break;
        }

        if (msg[0] != '\0')
            // send(sock, msg, strlen(msg), 0);
            send(sock, msg_en_nombres, strlen(msg), 0);

        free(msg_en_nombres);
    }
    return NULL;
}

int main(void) {
    int client_fd;
    struct sockaddr_in serv_addr;
    pthread_t thread_envoyer;

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
        0) {
        perror("connect");
        return 1;
    }

    printf("Connecté au serveur\n");
    printf("Tape \"exit\" pour quitter\n");

    pthread_create(&thread_envoyer, NULL, envoyer_messages, &client_fd);
    recevoir_messages(client_fd);

    // pthread_join(thread_envoyer, NULL);

    pthread_cancel(thread_envoyer);

    close(client_fd);
    printf("Client fermé\n");

    return 0;
}
