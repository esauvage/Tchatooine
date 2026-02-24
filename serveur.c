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
#include <natpmp.h>

#define PORT 1237
#define BUFFER_SIZE 1024

struct data_envoyer_messages {
    int fd;
    char *pseudo;
};

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
    }
    fclose(f);
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
            strcpy((char *)cle, (char *)data);
        }
    }
    fclose(f);
}

/*void convertir_msg(uint8_t *msg_en_nombres, char *msg) {
    const uint len_msg = strlen(msg);
    for (uint i = 0; i < len_msg; ++i) {
        msg_en_nombres[i] = (uint8_t)msg[i];
    }
}*/

void *envoyer_messages(void *arg) {
    struct data_envoyer_messages data = *(struct data_envoyer_messages *)arg;
    char msg[BUFFER_SIZE];

    struct chacha20_context ctx;

    uint8_t nonce[12];
    uint8_t cle[32];
    uint8_t pseudo_chiffre[BUFFER_SIZE];

    generer_nonce(nonce);
    generer_cle(cle);

    memcpy(pseudo_chiffre, data.pseudo, strlen(data.pseudo));

    chacha20_init_context(&ctx, cle, nonce, 0);
    chacha20_xor(&ctx, pseudo_chiffre, strlen(data.pseudo));

           // On envoie le pseudo
    send(data.fd, pseudo_chiffre, strlen(data.pseudo), 0);

    while (1) {
        // memset(msg, 0, BUFFER_SIZE);
        msg[0] = 0;

        if (fgets(msg, BUFFER_SIZE, stdin) == NULL)
            break;

        size_t len = strlen(msg);
        if (len > 0 && msg[len - 1] == '\n')
            msg[len - 1] = '\0';

        uint8_t *msg_en_nombres =
            (uint8_t *)malloc(strlen(msg) * sizeof(uint8_t));

        memcpy(msg_en_nombres, msg, strlen(msg));
        // convertir_msg(msg_en_nombres, msg);

        chacha20_init_context(&ctx, cle, nonce, 0);
        chacha20_xor(&ctx, msg_en_nombres, strlen(msg));

        printf("%s : %s\n", data.pseudo, msg);

        if (strcmp(msg, "exit") == 0) {
            // send(sock, msg, strlen(msg), 0);
            send(data.fd, msg_en_nombres, strlen(msg), 0);
            break;
        }

        if (msg[0] != '\0')
            // send(sock, msg, strlen(msg), 0);
            send(data.fd, msg_en_nombres, strlen(msg), 0);

        free(msg_en_nombres);
    }
    return NULL;
}

void recevoir_messages(int client_sock) {
    char buffer[BUFFER_SIZE];
    uint8_t msg_dechiffre[BUFFER_SIZE];
    ssize_t bytes;

    struct chacha20_context ctx;

    uint8_t nonce[12];
    uint8_t cle[32];

    generer_nonce(nonce);
    generer_cle(cle);

    char pseudo[BUFFER_SIZE];
    char pseudo_dechiffre[BUFFER_SIZE];

    ssize_t nbLues = read(client_sock, pseudo, BUFFER_SIZE);
    pseudo[nbLues] = '\0';

    memcpy(pseudo_dechiffre, pseudo, BUFFER_SIZE);

    chacha20_init_context(&ctx, cle, nonce, 0);
    chacha20_xor(&ctx, pseudo_dechiffre, strlen(pseudo));

    printf("Pseudo : %s\n", pseudo_dechiffre);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        memset(msg_dechiffre, 0, BUFFER_SIZE);

        bytes = read(client_sock, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) {
            printf("%s déconnecté\n", pseudo_dechiffre);
            break;
        }

        buffer[bytes] = '\0';

               // convertir_msg(msg_dechiffre, buffer);
        memcpy(msg_dechiffre, buffer, strlen(buffer));

        chacha20_init_context(&ctx, cle, nonce, 0);
        chacha20_xor(&ctx, msg_dechiffre, strlen(buffer));

        if (strcmp((char *)msg_dechiffre, "exit") == 0) {
            printf("%s a quitté\n", pseudo_dechiffre);
            break;
        }

        printf("%s : %s\n", pseudo_dechiffre, msg_dechiffre);
    }
}

int cli_parser(int argc, char **argv, char pseudo[BUFFER_SIZE]) {
    if (argc > 2) {
        if (strcmp(argv[1], "--pseudo") == 0) {
            strcpy(pseudo, argv[2]);

            return 1;
        }
    } else {
        puts("Veuillez indiquer un pseudo avec \"./serveur --pseudo \"votre "
             "pseudo\"\"");
    }
    return 0;
}

void redirect(uint16_t *privateport, uint16_t *publicport, natpmp_t *natpmp)
{
    // int r;
    // natpmp_t natpmp;
    // natpmpresp_t response;
    // initnatpmp(&natpmp, 0, 0);
    // sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, privateport, publicport, 3600);
    // do {
    //     fd_set fds;
    //     struct timeval timeout;
    //     FD_ZERO(&fds);
    //     FD_SET(natpmp.s, &fds);
    //     getnatpmprequesttimeout(&natpmp, &timeout);
    //     select(FD_SETSIZE, &fds, NULL, NULL, &timeout);
    //     r = readnatpmpresponseorretry(&natpmp, &response);
    // } while(r==NATPMP_TRYAGAIN);

           // printf("mapped public port %hu to localport %hu liftime %u\n",
           //        response.pnu.newportmapping.mappedpublicport,
           //        response.pnu.newportmapping.privateport,
           //        response.pnu.newportmapping.lifetime);
           // closenatpmp(&natpmp);
    natpmpresp_t response;
    struct in_addr publicaddress;
    enum { Sinit=0, Ssendpub, Srecvpub, Ssendmap, Srecvmap, Sdone, Serror=1000 } natpmpstate = Sinit;
    int r;
    int lifetime = 3600;
    uint32_t mappinglifetime;
    if(initnatpmp(natpmp, 0, 0) < 0)
        natpmpstate = Serror;
    else
        natpmpstate = Ssendpub;
    char finished_all_init_stuff = 0;
    while(!finished_all_init_stuff) {
        switch(natpmpstate) {
        case Ssendpub:
            if(sendpublicaddressrequest(natpmp)<0)
                natpmpstate = Serror;
            else
                natpmpstate = Srecvpub;
            break;
        case Srecvpub:
            r = readnatpmpresponseorretry(natpmp, &response);
            if(r<0 && r!=NATPMP_TRYAGAIN)
                natpmpstate = Serror;
            else if(r!=NATPMP_TRYAGAIN) {
                memcpy(&publicaddress, &response.pnu.publicaddress.addr, sizeof(struct in_addr));
                natpmpstate = Ssendmap;
            }
            break;
        case Ssendmap:
            if(sendnewportmappingrequest(natpmp, NATPMP_PROTOCOL_TCP, *privateport, *publicport, lifetime)<0)
                natpmpstate = Serror;
            else
                natpmpstate = Srecvmap;
            break;
        case Srecvmap:
            r = readnatpmpresponseorretry(natpmp, &response);
            if(r<0 && r!=NATPMP_TRYAGAIN)
                natpmpstate = Serror;
            else if(r!=NATPMP_TRYAGAIN) {
                *publicport = response.pnu.newportmapping.mappedpublicport;
                *privateport = response.pnu.newportmapping.privateport;
                mappinglifetime = response.pnu.newportmapping.lifetime;
                // closenatpmp(natpmp);
                natpmpstate = Sdone;
            }
            finished_all_init_stuff++;
            break;
        }
        // printf("natpmpstate : %d\n", natpmpstate);
    }
    // printf("natpmpstate : %d", natpmpstate);
}

int main(int argc, char **argv) {
    natpmp_t natpmp;
    uint16_t portPublic = 1237;
    uint16_t portPrive = 1237;

    redirect(&portPrive, &portPublic, &natpmp);

    char pseudo[BUFFER_SIZE];
    if (cli_parser(argc, argv, pseudo)) {
        printf("Pseudo : %s\n", pseudo);
    } else {
        return 0;
    }

    int mode = 0; // 0 : client, 1 : serveur
    int fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int opt = 1;

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(portPublic);

    // 87.88.38.108
    if (inet_pton(AF_INET, "87.88.38.108", &address.sin_addr) <= 0) {
        perror("inet_pton");
        mode = 1;
    }

    if (connect(client_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        // perror("connect");
        // return 1;
        puts("Pair non connecté, passage en mode serveur...");
        mode = 1;
    }
    else
    {
        puts("Connecté au serveur avec succès");
    }

    puts("Oui !");

    if (mode == 1)
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in address2;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        address2.sin_family = AF_INET;
        address2.sin_addr.s_addr = INADDR_ANY;
        address2.sin_port = htons(portPrive);

        if (bind(fd, (struct sockaddr *)&address2, sizeof(address2)) < 0) {
            perror("bind");
            exit(EXIT_FAILURE);
        }

        if (listen(fd, 1) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }
        printf("Serveur en attente sur le port %d\n", portPrive);
        client_fd = accept(fd, (struct sockaddr *)&address2, &addrlen);
        if (client_fd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("Client connecté\n");
    }

    struct data_envoyer_messages datas;
    datas.fd = client_fd;
    datas.pseudo = (char *)malloc(BUFFER_SIZE);
    strcpy(datas.pseudo, pseudo);

    pthread_t thread_envoyer;
    pthread_create(&thread_envoyer, NULL, envoyer_messages, &datas);
    recevoir_messages(client_fd);

    pthread_cancel(thread_envoyer);

    if (mode == 1)
        close(fd);
    close(client_fd);

    printf("Tchatooine fermé\n");
    free(datas.pseudo);

    closenatpmp(&natpmp);
    return 0;
}
