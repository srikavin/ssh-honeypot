#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#define CHILD_TIMEOUT_SEC 20

void handleConnection(ssh_session sshSession, FILE *loginLogFile, FILE *ipLogFile);

static volatile int running = 1;
static ssh_bind sshBind;

void intHandler() {
    running = 0;
    ssh_bind_free(sshBind);
    exit(0);
}

void childTimeoutHandler() {
    printf("Child process timed out after %d seconds\n", CHILD_TIMEOUT_SEC);
    exit(0);
}


int main(int argc, char **argv) {
    if (argc < 5) {
        printf("Usage: %s <port> <rsa_host_key_file> <login_log_file> <ip_log_file>\n", argv[0]);
        exit(-1);
    }

    //open login logfile
    FILE *logFile = fopen(argv[3], "a");
    //open ip log file
    FILE *ipLogFile = fopen(argv[4], "a");

    // Shut down cleanly on CTRL+C
    signal(SIGINT, intHandler);

    sshBind = ssh_bind_new();

    // Configure ssh_bind
    ssh_bind_options_set(sshBind, SSH_BIND_OPTIONS_BINDPORT_STR, argv[1]);
    ssh_bind_options_set(sshBind, SSH_BIND_OPTIONS_RSAKEY, argv[2]);

    if (ssh_bind_listen(sshBind) < 0) {
        fprintf(stderr, "Failed to bind to port %s: %s\n", argv[1], ssh_get_error(sshBind));
        ssh_bind_free(sshBind);
        exit(1);
    }

    while (running) {
        ssh_session sshSession = ssh_new();

        if (ssh_bind_accept(sshBind, sshSession) != SSH_OK) {
            fprintf(stderr, "Failed to accept incoming connection: %s\n", ssh_get_error(sshBind));
            ssh_free(sshSession);
            continue;
        }

        if (ssh_handle_key_exchange(sshSession) != SSH_OK) {
            fprintf(stderr, "Failed during key exchange: dle_key_exchange: %s\n", ssh_get_error(sshSession));
            ssh_free(sshSession);
            continue;
        }

        if (fork() == 0) {
            // kill child process after certain time to mitigate dos attacks
            alarm(CHILD_TIMEOUT_SEC);
            signal(SIGALRM, childTimeoutHandler);
            handleConnection(sshSession, logFile, ipLogFile);
        }
    }

    ssh_bind_free(sshBind);
    return 0;
}

void logIpAddress(ssh_session sshSession, FILE *ipLogFile) {
    struct sockaddr_in address;
    socklen_t addressSize = sizeof(address);

    getpeername(ssh_get_fd(sshSession), (struct sockaddr *) &address, &addressSize);

    char ipString[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(address.sin_addr), ipString, INET_ADDRSTRLEN);
    fprintf(ipLogFile, "%s\n", ipString);
    fflush(ipLogFile);
}

void handleConnection(ssh_session sshSession, FILE *loginLogFile, FILE *ipLogFile) {
    logIpAddress(sshSession, ipLogFile);

    while (running) {
        ssh_message message = ssh_message_get(sshSession);

        if (!message) {
            // error or timed out
            break;
        }

        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            int subtype = ssh_message_subtype(message);

            if (subtype == SSH_AUTH_METHOD_PASSWORD) {
                // log username and password and reject attempt to allow more attempts by bots
                const char *user = ssh_message_auth_user(message);
                const char *pass = ssh_message_auth_password(message);

                fprintf(loginLogFile, "%s:%s\n", user, pass);
                fflush(loginLogFile);
            }

            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    ssh_free(sshSession);
}
