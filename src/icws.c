#define _GNU_SOURCE
#include <strings.h>
#include <bits/types/siginfo_t.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include "parse.h"

#define MAXBUF 8192
#define DEBUG 1
#define LISTEN_QUEUE 5
#define ENVVAR 21

typedef struct sockaddr SA;
typedef struct stat STAT;
typedef struct tm TM;
typedef struct pollfd POLL;
typedef struct connInfo {
    char* addr;
    int connFd;
}connInfo;

// Status of the server
int running = 1;

int listenFd;

// Command line arguments
char* port;
char* serverRoot;
int timeout;
int numThreads;
char* cgiHandler;

// Work queue
connInfo* work_q;
int qSize;
int head = 0;
int tail = 0; 
int workCount = 0;

// Mutex and Conditional variables
pthread_t* workers;
pthread_mutex_t mutexParse;
pthread_mutex_t mutexQ;
pthread_cond_t condQ;


int open_listenfd(char *port) {
    struct addrinfo hints;
    struct addrinfo* listp;

    memset(&hints, 0, sizeof(struct addrinfo));
    /* Look to accept connect on any IP addr using this port no */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV; 
    int retCode = getaddrinfo(NULL, port, &hints, &listp);

    if (retCode < 0) {
        fprintf(stderr, "Error: %s\n", gai_strerror(retCode));
        exit(-1);
    }

    int listenFd;
    struct addrinfo *p;
    for (p=listp; p!=NULL; p = p->ai_next) {
        if ((listenFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue; /* This option doesn't work; try next */

        int optVal = 1;
        /* Alleviate "Address already in use" by allowing reuse */
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR,
                  (const void *) &optVal, sizeof(int));

        if (bind(listenFd, p->ai_addr, p->ai_addrlen) == 0)
            break; /* Yay, success */

        close(listenFd); /* Bind failed, close this, then next */
    }
    
    freeaddrinfo(listp);

    if (!p) 
        return -1; /* None of them worked. Meh */

    /* Make it ready to accept incoming requests */
    if (listen(listenFd, LISTEN_QUEUE) < 0) {
        close(listenFd);
        return -1;
    }

    /* All good, return the file descriptor */
    return listenFd;
}

void write_all(int connFd, char *buf, size_t len) {
    size_t toWrite = len;

    while (toWrite > 0) {
        ssize_t numWritten = write(connFd, buf, toWrite);
        if (numWritten < 0) { fprintf(stderr, "Meh, can't write\n"); return ;}
        toWrite -= numWritten;
        buf += numWritten;
    }
}


void setEnvVar(char** env, Request request, connInfo data) {
    char* headers[11] = {
        "content-length", "content-type", "accept", "referer", 
        "accept-encoding", "accept-language", "accept-charset", "host",
        "cookie", "user-agent", "connection"
    };
    char* envVar[ENVVAR] = {
        "CONTENT_LENGTH", "CONTENT_TYPE", "GATEWAY_INTERFACE", "PATH_INFO",
        "QUERY_STRING", "REMOTE_ADDR", "REQUEST_METHOD", "REQUEST_URI",
        "SCRIPT_NAME", "SERVER_PORT", "SERVER_PROTOCOL", "SERVER_SOFTWARE",
        "HTTP_ACCEPT", "HTTP_REFERER", "HTTP_ACCEPT_ENCODING", "HTTP_ACCEPT_LANGUAGE",
        "HTTP_ACCEPT_CHARSET", "HTTP_HOST", "HTTP_COOKIE", "HTTP_USER_AGENT",
        "HTTP_CONNECTION"
    };
    // Preset every value with null string
    char* envValue[ENVVAR];
    for (int i=0; i<ENVVAR; i++) {
        envValue[i] = "";
    }
    
    // Extract query
    char useless[MAXBUF/8] = {0};
    char query[MAXBUF/8] = {0};
    sscanf(request.http_uri, "%[^?]?%s",useless, query);
    
    // Set some of the variables
    envValue[2] = "CGI/1.1";
    envValue[3] = "/cgi/";
    envValue[4] = query;
    envValue[5] = data.addr;
    envValue[6] = request.http_method;
    envValue[7] = request.http_uri;
    envValue[8] = cgiHandler;
    envValue[9] = port;
    envValue[10] = "HTTP/1.1";
    envValue[11] = "ICWS";

    // Set Variables where its value is read from the request headers
    for (int i=0; i<request.header_count; i++) {
        int c;
        for (int j=0; j<11; j++) {
            if (!strcasecmp(request.headers[i].header_name, headers[j])) c = j;
        }
        switch (c) {
            case 0:
                envValue[0] = request.headers[i].header_value;
                break;
            case 1:
                envValue[1] = request.headers[i].header_value;
                break;
            case 2:
                envValue[12] = request.headers[i].header_value;
                break;
            case 3:
                envValue[13] = request.headers[i].header_value;
                break;
            case 4:
                envValue[14] = request.headers[i].header_value;
                break;
            case 5:
                envValue[15] = request.headers[i].header_value;
                break;
            case 6:
                envValue[16] = request.headers[i].header_value;
                break;
            case 7:
                envValue[17] = request.headers[i].header_value;
                break;
            case 8:
                envValue[18] = request.headers[i].header_value;
                break;
            case 9:
                envValue[19] = request.headers[i].header_value;
                break;
            case 10:
                envValue[20] = request.headers[i].header_value;
                break;
        }
    }
    // Combine all headers and values in to *env[]
    for (int i=0; i<ENVVAR; i++) {
        env[i] = malloc(MAXBUF/8);
        sprintf(env[i], "%s=%s", envVar[i], envValue[i]);
    }
    // NULL terminated array
    env[ENVVAR] = NULL;
}


void create_response(char*buf, int code, char* status, char* connType, STAT* finfo ,char* MIME) {
    // Get current time in HTTP format
    char nowbuf[50];
    time_t now = time(NULL);
    TM nowgmt;
    gmtime_r(&now, &nowgmt);
    strftime(nowbuf, 50, "%a, %d %b %Y %H:%M:%S %Z", &nowgmt);
    
    if (code >= 400) {
      sprintf(buf, "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Server: ICWS\r\n"
            "Connection: %s\r\n",
            code, status, nowbuf, connType);
    }

    else {
        // Turn Last Modified in to HTTP format
        char lmbuf[50];
        TM lastMod;
        gmtime_r(&finfo->st_mtime, &lastMod);
        strftime(lmbuf, 50, "%a, %d %b %Y %H:%M:%S %Z", &lastMod);

        sprintf(buf, "HTTP/1.1 %d %s\r\n"
                "Date: %s\r\n"
                "Server: ICWS\r\n"
                "Connection: %s\r\n"
                "Content-length: %lld\r\n"
                "Content-type: %s\r\n"
                "Last-Modified: %s\r\n\r\n", 
                code, status, nowbuf, connType, (long long)finfo->st_size, MIME, lmbuf);
    }
}

char* get_mime(char* uri) {
    char* ext;
    ext = strrchr(uri, '.');
    if (!strcmp(ext, ".html") || !strcmp(ext, ".htm")) 
        return "text/html";
    else if (!strcmp(ext, ".css"))
        return "text/css";
    else if (!strcmp(ext, ".txt"))
        return "text/plain";
    else if (!strcmp(ext, ".js"))
        return "text/javascript";
    else if (!strcmp(ext, ".jpg") || !strcmp(ext, "jpeg"))
        return "image/jpeg";
    else if (!strcmp(ext, ".png"))
        return "image/png";
    else if (!strcmp(ext, ".gif"))
        return "image/gif";

    return "application/octet-stream";
}

void respondErr(int connFd, int errCode, char* status, char* connType) {
    char buf[MAXBUF];
    create_response(buf, errCode, status, connType, NULL, NULL);
    write_all(connFd, buf, strlen(buf));

    if (DEBUG) printf("%s\n", buf);
}

// content: 0 = respond without content
//          else = respond with content
void respond(int connFd, char* uri, int content, char* connType) {
    char buf[MAXBUF];
    char* MIME= get_mime(uri);
    STAT finfo;

    printf("%s\n", uri);
  
    int objFd = open(uri, O_RDONLY);
   
    if (objFd < 0) {
        create_response(buf, 404, "Not Found", connType, NULL, NULL);
        write_all(connFd, buf, strlen(buf));
    } 

    else {
	    fstat(objFd, &finfo);

        create_response(buf, 200, "OK", connType, &finfo, MIME);
	    write_all(connFd, buf, strlen(buf));
        
        if (content) {
            char obj[MAXBUF];
            ssize_t nRead;
            ssize_t toRead = finfo.st_size;
            while (toRead > 0) {
                nRead = read(objFd, obj, MAXBUF);
                if (nRead < 0) break;
                toRead -= nRead;
                write_all(connFd, obj, nRead); 
            }
        }
    }
    
    if (DEBUG) printf("%s\n", buf);

    close(objFd);
}

// For pipelined request
int shiftBuf(char* buf, ssize_t bufoffset, ssize_t bytesRead) {
    // Loop until end of buf
    ssize_t bytesRemain = bytesRead - bufoffset;
    int i;
    for (i=0; i<bytesRemain; i++) {
        buf[i] = buf[bufoffset++];
    }
    return i;
}

void fail_exit(char *msg) { fprintf(stderr, "%s\n", msg); exit(-1); }

void fail_respond(char *msg, connInfo data) { 
    fprintf(stderr, "%s\n", msg); 
    respondErr(data.connFd, 500, "Internal Server Error", "Close");
}

void callCgi(Request* request, connInfo data, char* bodyMsg) {
    int c2pFds[2]; /* Child to parent pipe */
    int p2cFds[2]; /* Parent to child pipe */

    if (pipe(c2pFds) < 0) { fprintf(stderr, "c2p pipe failed.\n"); return;}
    if (pipe(p2cFds) < 0) { fprintf(stderr, "p2c pipe failed.\n"); return;}

    char* env[ENVVAR+1];
    setEnvVar(env, *request, data);

    int pid = fork();

    if (pid < 0) fail_exit("Fork failed.");
    if (pid == 0) { /* Child - set up the conduit & run inferior cmd */

        /* Wire pipe's incoming to child's stdin */
        /* First, close the unused direction. */
        if (close(p2cFds[1]) < 0) fail_exit("failed to close p2c[1]");
        if (p2cFds[0] != STDIN_FILENO) {
            if (dup2(p2cFds[0], STDIN_FILENO) < 0)
                fail_exit("dup2 stdin failed.");
            if (close(p2cFds[0]) < 0)
                fail_exit("close p2c[0] failed.");
        }

        /* Wire child's stdout to pipe's outgoing */
        /* But first, close the unused direction */
        if (close(c2pFds[0]) < 0) fail_exit("failed to close c2p[0]");
        if (c2pFds[1] != STDOUT_FILENO) {
            if (dup2(c2pFds[1], STDOUT_FILENO) < 0)
                fail_exit("dup2 stdin failed.");
            if (close(c2pFds[1]) < 0)
                fail_exit("close pipeFd[0] failed.");
        }

        char* inferiorArgv[] = {cgiHandler, NULL};
        if (execvpe(inferiorArgv[0], inferiorArgv, env) < 0)
            fail_exit("exec failed.");
    }
    else { /* Parent - send a random message */
        /* Close the write direction in parent's incoming */
        if (close(c2pFds[1]) < 0) { fail_respond("failed to close c2p[1]", data); return; }

        /* Close the read direction in parent's outgoing */
        if (close(p2cFds[0]) < 0) { fail_respond("failed to close p2c[0]", data); return; }

        /* Write a message to the child - replace with write_all as necessary */
        if (bodyMsg) write_all(p2cFds[1], bodyMsg, strlen(bodyMsg));

        /* Close this end, done writing. */
        if (close(p2cFds[1]) < 0) { fail_respond("failed to close p2c[1]", data); return; }

        char buf[MAXBUF+1];
        ssize_t numRead;
        /* Begin reading from the child */
        while ((numRead = read(c2pFds[0], buf, MAXBUF))>0) {
            // send data to the client
            write_all(data.connFd, buf, numRead);
            printf("Parent saw %ld bytes from child...\n", numRead);
            buf[numRead] = '\x0'; /* Printing hack; won't work with binary data */
            printf("-------\n");
            printf("%s", buf);
            printf("-------\n");
        }
        /* Close this end, done reading. */
        if (close(c2pFds[0]) < 0) { fail_respond("failed to close c2p[0]", data); return; }

        /* Wait for child termination & reap */
        int status;

        if (waitpid(pid, &status, 0) < 0) { fail_respond("waitpid failed", data); return; }

        // respond 500 if CGI fails
        if (WEXITSTATUS(status) == -1) respondErr(data.connFd, 500, "Internal Server Error", "Close");

        // Free all malloc'd *env[]
        for (int i=0; i<ENVVAR; i++) {
            free(env[i]);
        }
        
        printf("Child exited... parent's terminating as well.\n");
    }
}

void serve_http(connInfo data, char* rootFolder) {
    int connFd = data.connFd;

    char* buf = malloc(sizeof(char)*(MAXBUF));
    ssize_t bufsize = MAXBUF;
    ssize_t bytesRead = 0;
    char line[MAXBUF];
    ssize_t lineoffset = 0;
    ssize_t readRet = 0;
    // Connection type
    int close = 0;
    // Initializing poll
    POLL pfd[1];
    pfd[0].fd = connFd;
    pfd[0].events = POLLIN;
    while (!close) {
        char* connType;
        ssize_t bufoffset = 0;
        ssize_t headerssize = 0;
        ssize_t bodysize = 0;
        // Check if request line is already read.
        int reqline = 1;
        // Get current start time
        time_t start = time(NULL);
        while (1 && (readRet >= 0)) {
            // Timer for non-meaningful request
            time_t diff = time(NULL) - start;
            if (diff > (timeout)) {
                respondErr(connFd, 408, "Request Time-out", "Close");
                close = 1;
                break;
            }
            // Finding crlf (end of headers)
            int crlf = 0;
            // LOOP until crlf line is found.
            for (int i=0; i<readRet; i++) {
                line[lineoffset++] = buf[bufoffset];
                if (!reqline) headerssize++;
                if (buf[bufoffset++] == '\n') {
                    // The remaining lines are header
                    if (reqline) reqline = 0;

                    line[lineoffset] = '\0';
                    if(!strcmp(line, "\r\n")) {
                        crlf = 1; 
                        lineoffset = 0;
                        break;
                    }
                    lineoffset = 0;
                }
            }

            readRet = 0;

            if (crlf == 1) break;

            if (bytesRead > bufsize/2) {
            bufsize *= 2;
            buf = (char*) realloc(buf, sizeof(char)*bufsize);
            }

            
            // Waiting for a while before reject client if nothing arrived.
            int pollret;
            pollret = poll(pfd, 1, timeout*1000);
            if (pollret < 0) {
                perror("poll failed");
            }
            else if (pollret==0) {
                respondErr(connFd, 408, "Request Time-out", "Close");
                close = 1;
                break;
            }
            else{
                if (pfd[0].revents & POLLIN) {
                    readRet = read(connFd, buf+bytesRead, MAXBUF);
                    bytesRead += readRet;
                } 
            }
        }


        if (readRet < 0) {
            fprintf(stderr, "Cannot read\n");
            return;
        }

        if (close) break;

        pthread_mutex_lock(&mutexParse);
        Request* request = parse(buf, bufoffset, connFd);
        pthread_mutex_unlock(&mutexParse);

        // Malformed request responded with 400
        if (request==NULL) {
            respondErr(connFd, 400, "Bad Request", "Close");
            close = 1;
            continue;
        }

        if (DEBUG) printf("LOG: %s %s %s\n", request->http_method, request->http_uri, request->http_version);
        
        int i;
        // Check for Host header
        int host = 0;
        // Check for Connection header
        int conn = 0;
        
        if (strcasecmp(request->http_version, "HTTP/1.1")) {
            respondErr(connFd, 505, "HTTP Version not supported", "Close");
            close = 1;
        }
        else {
            for (i=0; i<request->header_count; i++) {
                if (DEBUG) printf("%s: %s\n", request->headers[i].header_name, request->headers[i].header_value);
                if (!strcasecmp(request->headers[i].header_name, "Content-Length")) {
                    bodysize = atoi(request->headers[i].header_value);
                }
                else if (!strcasecmp(request->headers[i].header_name, "Host")) host = 1;
                else if (!strcasecmp(request->headers[i].header_name, "Connection")) {
                    conn = 1;
                    connType = request->headers[i].header_value;
                    if (!strcasecmp(connType, "Close")) close = 1;
                }
            }

            // If no 'connection' header, treat it as keep-alive
            if (conn == 0) connType = "keep-alive";

            // i == 0: request headers is NULL
            // host == 0: no Host header
            if (host == 0) {
                respondErr(connFd, 400, "Bad Request", "Close");
                close = 1;
            }
            // reject header > 8192 bytes
            else if (headerssize <= MAXBUF) {
                // Determine the method
                int get = 0;
                int head = 0;
                int post = 0;
                get = !strcasecmp(request->http_method, "GET");
                head = !strcasecmp(request->http_method, "HEAD"); 
                post = !strcasecmp(request->http_method, "POST");

                // CGI requests
                char path[MAXBUF/8];
                if (sscanf(request->http_uri, "/cgi/%s", path)) {
                    // Extract body messages
                    char bodyMsg[bodysize];
                    for (int j=0; j<bodysize; j++) {
                        bodyMsg[j] = buf[bufoffset++];
                    }
                    if (get | head | post) {
                        if (bodysize) callCgi(request, data, bodyMsg);
                        else callCgi(request, data, NULL);
                        close = 1;
                    }
                    else {
                        respondErr(connFd, 501, "Not Implemented", "Close");
                        close = 1;
                    }
                }
                // Normal requests
                else {
                    // If method is GET
                    if (get) {
                        char root[strlen(rootFolder)];
                        strcpy(root, rootFolder);
                        respond(connFd, strcat(root, request->http_uri), 1, connType);
                    }
                    // If method is HEAD
                    else if (head) {
                        char root[strlen(rootFolder)];
                        strcpy(root, rootFolder);
                        // respond with only header
                        respond(connFd, strcat(root, request->http_uri), 0, connType);
                    }
                    else {
                        respondErr(connFd, 501, "Not Implemented", "Close");
                        close = 1;
                    }
                }

            }
        }

        bytesRead = shiftBuf(buf, bufoffset, bytesRead);
        readRet = bytesRead;

        free(request->headers);
        free(request);
    }
    free(buf);
}



void addJob(connInfo data) {
    pthread_mutex_lock(&mutexQ);
    if (workCount < qSize) {
        work_q[tail] = data;
        tail = (tail+1) % qSize;
        workCount++;
    }
    pthread_mutex_unlock(&mutexQ);
    pthread_cond_signal(&condQ);
}

int removeJob(connInfo* data) {
    int success = (workCount) ? 1 : 0;
    if (success) {
        *data = work_q[head];
        head = (head+1) % qSize;
        workCount--;
    }
    return success;
}

void signalHandler(int sig, siginfo_t *sip, void *notused) {
    printf("\nServing current clients before exiting\n"
            "Please wait a sec...\n"); fflush(stdout);
    
    // Close all connection waiting in the queue
    pthread_mutex_lock(&mutexQ);
    connInfo data;
    for (int i=0; i<workCount; i++) {
        removeJob(&data);
        close(data.connFd);
    }
    pthread_mutex_unlock(&mutexQ);

    // Send in poison pills
    for (int i=0; i<numThreads; i++) {
        connInfo data;
        data.connFd = -1;
        addJob(data);
    }

    // Jump out of accept() in main thread
    close(listenFd);
    // Close the loop in main thread
    running = 0;
}

void createSigHandler() {
    struct sigaction action;
    action.sa_sigaction = signalHandler;
    sigfillset (&action.sa_mask);
    action.sa_flags = SA_SIGINFO;

    sigaction(SIGINT, &action, NULL);
}

void* startThread(void* args) {
    while(1) {
        pthread_mutex_lock(&mutexQ);
        connInfo data;
        while (!removeJob(&data)) {
            pthread_cond_wait(&condQ, &mutexQ);
        }
        pthread_mutex_unlock(&mutexQ);
      
        // Thread exit
        if (data.connFd < 0) break;
        serve_http(data, serverRoot);
        close(data.connFd);
    }
    return NULL;
}

void getArg(int argc, char* argv[]) {
    static struct option long_options[] = 
    {
        {"port", required_argument, NULL, 'p'},
        {"root", required_argument, NULL, 'r'},
        {"numThreads", required_argument, NULL, 'n'},
        {"timeout", required_argument, NULL, 't'},
        {"cgiHandler", required_argument, NULL, 'c'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "p:v:n:t:", long_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                port = optarg;
                break;
            case 'r':
                serverRoot = optarg;
                break;
            case 'n':
                numThreads = atoi(optarg);
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'c':
                cgiHandler = optarg;
                break;
            case '?':
                perror("invalid argument!");
                exit(EXIT_FAILURE);
        }
    }

    // If one of the argument is missing(NULL) exit the program
    if (!port || !serverRoot || !numThreads || !timeout) {
        char* errmsg;
        if (!port) errmsg = "Port argument is missing!";
        else if (!serverRoot) errmsg = "serverRoot argument is missing";
        else if (!numThreads) errmsg = "numThreads argument is missing";
        else if (!timeout) errmsg = "timeout argument is missing";
        
        perror(errmsg); exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    // Process command line arguments
    getArg(argc, argv);

    // Initializing signal handler
    createSigHandler();

    // Initializing mutex and conditional variables
    pthread_mutex_init(&mutexQ, NULL);
    pthread_mutex_init(&mutexParse, NULL);
    pthread_cond_init(&condQ, NULL);

    // Initializing worke queue
    qSize = numThreads;
    connInfo q[qSize*10];
    work_q = q;

    // Initializing threads
    pthread_t temp[numThreads];
    workers = temp;
    for (int i=0; i<numThreads; i++) {
        if (pthread_create(&workers[i], NULL, &startThread, NULL) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);   
        }
    }

    // Start accepting connections
    listenFd = open_listenfd(port);

    for(;;) {
        struct sockaddr_storage clientAddr;
        socklen_t clientLen = sizeof(struct sockaddr);

        int connFd = accept(listenFd, (SA *) &clientAddr, &clientLen);
        // Exiting program
        if (!running) break;
        if (connFd < 0) { fprintf(stderr, "Failed to accept\n"); continue; }

        char hostBuf[255], svcBuf[255];
        if (getnameinfo((SA *) &clientAddr, clientLen, 
                        hostBuf, MAXBUF, svcBuf, MAXBUF, NI_NUMERICHOST)==0) 
            printf("Connection from %s:%s\n", hostBuf, svcBuf);
        else
            printf("Connection from ?UNKNOWN?\n");

        connInfo data;
        data.addr = hostBuf;
        data.connFd = connFd;

        // add job to the queue
        addJob(data);
    
    }

    // Destroy all threads, mutex, and conditional variables;
    for (int i=0; i<numThreads; i++) {
        if (pthread_join(workers[i], NULL) != 0) 
            perror("Thread joining failed");
    }
    
    pthread_mutex_destroy(&mutexQ);
    pthread_mutex_destroy(&mutexParse);
    pthread_cond_destroy(&condQ);
    printf("Exiting...\n");

    return 0;
}

