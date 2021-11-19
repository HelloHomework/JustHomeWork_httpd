#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define _GNU_SOURCE

#define SERVER_STRING \
  "Server: justHomework/0.8.7 (Macintosh; Intel Mac OS X 10_15_7)\r\n"

#define BASIC_HEADER                   \
  "X-Frame-Options: SAMEORIGIN\r\n"    \
  "X-XSS-Protection: 1;mode=block\r\n" \
  "X-Content-Type-Options: 'nosniff'\r\n" \
  "Content-Security-Policy: script-src 'self' 'unsafe-eval' 'unsafe-inline'; worker-src 'self' blob:; frame-ancestors 'self' \r\n"\
  "Referrer-Policy: no-referrer-when-downgrade\r\n" \
  "Permissions-Policy: 	geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()\r\n"

#define DEFAULT_400_PAGE                                                       \
  "<HTML><TITLE>400 Bad Request</TITLE><HEAD><TITLE>server cannot or will "    \
  "not process the request due to something that is perceived to be a client " \
  "error</BODY></HTML>\r\n"

#define DEFAULT_404_PAGE                                                    \
  "<HTML><TITLE>404 Not Found</TITLE>\r\n<BODY><P>The server can not find " \
  "the requested resource.</P></BODY></HTML>\r\n"

#define DEFAULT_501_PAGE                                                   \
  "<HTML><HEAD><TITLE>Method Not Implemented</TITLE></HEAD><BODY><P>HTTP " \
  "request method not supported.</BODY></HTML>\r\n"

struct file_extensions {
  const char *extension;
  const char *filetype;
} extensions[] = {{".gif", "image/gif"},      {".jpg", "image/jpeg"},
                  {".jpeg", "image/jpeg"},    {".png", "image/png"},
                  {".zip", "image/zip"},      {".gz", "image/gz"},
                  {".tar", "image/tar"},      {".svg", "image/svg+xml"},
                  {".webp", "image/webp"},    {".ico", "image/x-icon"},
                  {".htm", "text/html"},      {".html", "text/html"},
                  {".exe", "text/plain"},     {".css", "text/css"},
                  {".js", "text/javascript"}, {0, 0}};

int init(in_port_t *port);
void accept_request(int client_socket);

// tools
int get_line(int sock, char *buf, int size);
void errorExit(const char *errorMessage);

// return headers
void unimplemented(int client_socket);
void not_found(int client_socket);
void bad_request(int client_socket);

// HTTP handler
void getHandler(int client_socket, const char *filename);
void postHandler(int client_socket, const char *path, const char *method,
                 const char *query);
void cat(int, FILE *);

/*
init() will finish create a socket and listen
*/
int init(in_port_t *port) {
  int httpd = 0;
  int on = 1;
  struct sockaddr_in name;

  httpd = socket(PF_INET, SOCK_STREAM, 0);
  if (httpd == -1) errorExit("init failed: socket");
  memset(&name, 0, sizeof(name));
  // use ipv4
  name.sin_family = AF_INET;
  // htons Network Byte Order -> Host Byte Order
  name.sin_port = htons(*port);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
    errorExit("init failed: setsockopt failed");
  }
  if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
    errorExit("init failed: bind");
  if (*port == 0) /* if dynamically allocating a port */
  {
    socklen_t namelen = sizeof(name);
    if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
      errorExit("init failed: getsockname");
    *port = ntohs(name.sin_port);
  }
  if (listen(httpd, 5) < 0) errorExit("listen");
  return (httpd);
}

// handle the after request
void accept_request(int client_socket) {
  char buf[1024];
  size_t numchars;
  char method[255];
  char url[255];
  char path[512];
  size_t i, j;
  struct stat st;
  int cgi = 0;  // becomes true if server decides this is a CGI
  int status = 0; // 0: unimplement 1: GET 2: POST
  char *query_string = NULL;

  // method
  numchars = get_line(client_socket, buf, sizeof(buf));
  i = 0;
  j = 0;
  while (!isspace((int)buf[i]) && (i < sizeof(method) - 1)) {
    method[i] = buf[i];
    i++;
  }
  j = i;
  method[i] = '\0';

#ifdef DEBUG
  printf("method: %s\n", method);
#endif

  if (strcasecmp(method, "GET") && strcasecmp(method, "POST")) {
    unimplemented(client_socket);
    return;
  }

  if (strcasecmp(method, "POST") == 0){
    status = 2;
    cgi = 1;
  }

  // cut url
  i = 0;
  while (isspace(buf[j]) && (j < numchars)) j++;
  while (!isspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars)) {
    url[i] = buf[j];
    i++;
    j++;
  }
  url[i] = '\0';

#ifdef DEBUG
  printf("url: %s\n", url);
#endif

  // cut cgi
  query_string = url;
    while ((*query_string != '?') && (*query_string != '\0')) query_string++;
    if (*query_string == '?') {
      cgi = 1;
      *query_string = '\0';
      query_string++;
    }

#ifdef DEBUG
  printf("query_string: %s\n", query_string);
#endif

  if (strcasecmp(method, "GET") == 0) 
    status = 1;

  sprintf(path, "htdocs%s", url);
  if (path[strlen(path) - 1] == '/') strcat(path, "index.html");
  if (stat(path, &st) == -1) {
    while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
      numchars = get_line(client_socket, buf, sizeof(buf));
    not_found(client_socket);
  } else {
    if ((st.st_mode & S_IFMT) == S_IFDIR) strcat(path, "/index.html");
    
    #ifdef DEBUG
    if(cgi == 1) printf("http query found\n");
    #endif

    if (status == 1)
      getHandler(client_socket, path);
    else if(status == 2)
      postHandler(client_socket, path, method, query_string);
    else
      bad_request(client_socket);

  }
  close(client_socket);
}

// handle all GET
void getHandler(int client_sock, const char *filename) {
  int numchars = 1;
  char buf[1024] = "A\0";
  char *extension = NULL;
  const char *filetype = NULL;

  while ((numchars > 0) && strcmp("\n", buf))  // drop other header
    numchars = get_line(client_sock, buf, sizeof(buf));

#ifdef DEBUG
  printf("filename: %s\n", filename);
  printf("serve_file: %s\n", buf);
#endif

  if ((extension = strcasestr(filename, ".")) != NULL) {
    for (int i = 0; extensions[i].extension != 0; ++i) {
      if (strstr(extension, extensions[i].extension) != NULL) {
        filetype = extensions[i].filetype;
        break;
      }
    }
#ifdef DEBUG
    printf("file extension: %s\n", extension);
#endif
  }

  // open file
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    not_found(client_sock);

    return;
  }

  struct stat statbuf;
  fstat(fd, &statbuf);

  // header
  int len = 0;

  write(client_sock, "HTTP/1.0 200 OK\r\n", strlen("HTTP/1.0 200 OK\r\n"));
  write(client_sock, SERVER_STRING, strlen(SERVER_STRING));
  // RFC-7231
  len = sprintf(buf, "Content-Type: %s\r\n",
                (filetype == NULL) ? "application/octet-stream" : filetype);
  write(client_sock, buf, len);
  len = sprintf(buf, "Content-Length: %lld\r\n", statbuf.st_size);
  write(client_sock, buf, len);
  write(client_sock, BASIC_HEADER, strlen(BASIC_HEADER));
  write(client_sock, "\r\n", strlen("\r\n"));

  char *filebuf = malloc(statbuf.st_size);
  // proceed with allocating memory and reading the file
  read(fd, filebuf, statbuf.st_size);
#ifdef DEBUF
  write(2, buf, statbuf.st_size);
#endif
  write(client_sock, filebuf, statbuf.st_size);
  free(filebuf);
  close(fd);
}

// POST to upload file
void postHandler(int client_socket, const char *path, const char *method,
                 const char *query) {
  char buf[256];
  char boundry[128];
  size_t boundryLen = 0;
  int contentLength = 0;
  // RFC1521 says that a boundary "must be no longer than 70 characters,
  // not counting the two leading hyphens".
  int len = 0;
  len = get_line(client_socket, buf, sizeof(buf));

  while ((len > 0) && strcmp("\n", buf)) {
    len = get_line(client_socket, buf, sizeof(buf));
#ifdef DEBUG
    write(2, buf, len);
#endif
    char *tmp = strcasestr(buf, "boundary=");
    if (tmp != NULL) {
      strncpy(boundry, tmp + strlen("boundary="), 127);
      boundryLen = strlen(boundry) - 1;
      if (boundry[boundryLen] == '\n') boundry[boundryLen] = '\0';
    }
    tmp = strcasestr(buf, "Content-Length:");
    if (tmp != NULL) {
      printf("OK!\n");
      long long lenTmp = atoll(tmp + strlen("Content-Length:"));
      if (lenTmp > INT_MAX || lenTmp < 0) {
        bad_request(client_socket);
        errorExit("POST: Content-Length over limit.\n");
      }
      contentLength = (int)lenTmp;
    }
  }

#ifdef DEBUG
  printf("Content-Length: %d\n", contentLength);
  printf("boundary: %s\n", boundry);
#endif

  ssize_t readLen = 1;
  ssize_t now = 0;

  char *payload = malloc(contentLength + 1024);
  char *payloadEnd = payload + contentLength - 1;

  memset(payload, 0, contentLength);
  while (readLen != 0 && now <= contentLength) {
    char *tmp = payload + now;
    if (tmp > payloadEnd) break;
    readLen = read(client_socket, tmp, contentLength);
    now += readLen;
  }

#ifdef DEBUG
  int debug_fd = open("./htdocs/debug.log", O_WRONLY | O_CREAT, 0644);
  size_t debug_writeLen = 0;
  debug_writeLen = write(debug_fd, payload, contentLength);
  printf("writeLen: %ld\n", debug_writeLen);
  close(debug_fd);
#endif

  char *head = memmem(payload, contentLength, boundry, boundryLen);
  char *tail = NULL;

  if (head != NULL) {
    contentLength = contentLength - (head - payload);
    tail = memmem(head + boundryLen + 1, contentLength, boundry, boundryLen);
  }

  if (head == NULL || tail == NULL) {
    bad_request(client_socket);
    errorExit("POST: payload format error\n");
  }

  while (tail != NULL && contentLength > 0 && tail <= payloadEnd) {
    char filepath[512] = "./htdocs/upload/";
    char filename[256];  // linux filename maximum length 256
    char *lineStart = head;
    char *lineEnd = strstr(head, "\r\n");
    while (lineEnd != NULL) {
      char *tmp = strnstr(lineStart, "filename=", lineEnd - lineStart);
      if (tmp != NULL) {
        int i = 0;
        tmp += 8;  // strlen("filename=") - 1
        while (tmp != lineEnd) {
          if (*tmp != '=' && *tmp != '\"') filename[i++] = *tmp;
          ++tmp;
          if (i == 256) break;
          if (*tmp == '\r' || *tmp == '\n') break;
        }
        filename[i] = '\0';
      }
      lineStart = lineEnd + 2;
      lineEnd = strstr(lineStart, "\r\n");
      if (lineEnd == lineStart) break;
    }
    lineEnd += 2;  // over \r\n
    strncat(filepath, filename, 511);

    printf("filepath: %s\n", filepath);

    int fd = open(filepath, O_WRONLY | O_CREAT, 0644);
    readLen = write(fd, lineEnd, tail - lineEnd - 4);  // ASLR * 2
#ifdef DEBUG
    printf("writeLen: %ld\n", readLen);
#endif

    close(fd);

    head = tail;
    if (tail + strlen(boundry) <= payloadEnd) {
      tail = memmem(head + strlen(boundry),
                    payloadEnd - tail - strlen(boundry) + 1, boundry,
                    strlen(boundry));
    }
  }

  free(payload);

  write(client_socket, "HTTP/1.0 200 OK\r\n", strlen("HTTP/1.0 200 OK\r\n"));
  write(client_socket, SERVER_STRING, strlen(SERVER_STRING));
  write(client_socket, BASIC_HEADER, strlen(BASIC_HEADER));
  write(client_socket, "\r\n", strlen("\r\n"));
}

// getline (CRLF version), return number of bytes
// code source : http://tinyhttpd.sourceforge.net
int get_line(int sock, char *buf, int size) {
  int i = 0;
  char c = '\0';
  int n;

  while ((i < size - 1) && (c != '\n')) {
    n = recv(sock, &c, 1, 0);
    if (n > 0) {
      if (c == '\r') {
        n = recv(sock, &c, 1, MSG_PEEK);
        if ((n > 0) && (c == '\n'))
          recv(sock, &c, 1, 0);
        else
          c = '\n';
      }
      buf[i] = c;
      i++;
    } else
      c = '\n';
  }
  buf[i] = '\0';

  return (i);
}

// method not implemnet
void unimplemented(int client_socket) {
  write(client_socket, "HTTP/1.0 501 Method Not Implemented\r\n",
        strlen("HTTP/1.0 501 Method Not Implemented\r\n"));
  write(client_socket, SERVER_STRING, strlen(SERVER_STRING));
  write(client_socket, "Content-Type: text/html\r\n",
        strlen("Content-Type: text/html\r\n"));
  write(client_socket, BASIC_HEADER, strlen(BASIC_HEADER));
  write(client_socket, "\r\n", strlen("\r\n"));
  write(client_socket, DEFAULT_501_PAGE, strlen(DEFAULT_501_PAGE));
}

// server can't find the requested resource.
void not_found(int client_socket) {
#ifdef DEBUG
  printf("404 NOT FOUND\n");
#endif

  // header
  int len = 0;
  char buf[1024];
  char filepath[] = "htdocs/error/404.html";

  // basic http header
  write(client_socket, "HTTP/1.0 404 NOT FOUND\r\n",
        strlen("HTTP/1.0 404 NOT FOUND\r\n"));
  write(client_socket, SERVER_STRING, strlen(SERVER_STRING));
  write(client_socket, "Content-Type: text/html\r\n",
        strlen("Content-Type: text/html\r\n"));
  write(client_socket, BASIC_HEADER, strlen(BASIC_HEADER));

  // open file
  int fd = open(filepath, O_RDONLY);

  if (fd == -1) {
    printf("customized 404 page not found\n");
    write(client_socket, "\r\n", strlen("\r\n"));
    write(client_socket, DEFAULT_404_PAGE, strlen(DEFAULT_404_PAGE));
    return;
  }

  struct stat statbuf;
  char *filebuf = malloc(statbuf.st_size);

  fstat(fd, &statbuf);

  len = sprintf(buf, "Content-Length: %lld\r\n", statbuf.st_size);
  write(client_socket, buf, len);
  write(client_socket, "\r\n", strlen("\r\n"));

  read(fd, filebuf, statbuf.st_size);
  write(client_socket, filebuf, statbuf.st_size);

  free(filebuf);

  return;
}

// Server cannot or will not process the request due to something that is
// perceived to be a client error
void bad_request(int client_socket) {
  write(client_socket, "HTTP/1.0 400 BAD REQUEST\r\n",
        strlen("HTTP/1.0 400 BAD REQUEST\r\n"));
  write(client_socket, SERVER_STRING, strlen(SERVER_STRING));
  write(client_socket, "Content-Type: text/html\r\n",
        strlen("Content-Type: text/html\r\n"));
  write(client_socket, BASIC_HEADER, strlen(BASIC_HEADER));
  write(client_socket, "\r\n", strlen("\r\n"));
  write(client_socket, DEFAULT_400_PAGE, strlen(DEFAULT_400_PAGE));
}

void errorExit(const char *errorMessage) {
  perror(errorMessage);
  exit(1);
}

int main(void) {
  int server_sock = -1;
  in_port_t port = 4000;

  int client_socket = -1;
  struct sockaddr_in client_name;

  socklen_t client_name_len = sizeof(client_name);
  pid_t pid;

  server_sock = init(&port);
  printf("httpd running on port %d\n", port);

  while (1) {
    client_socket =
        accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);
    if (client_socket == -1) errorExit("error: accept\n");

    // fork after accept
    if ((pid = fork()) < 0) {
      errorExit("fork error\n");
    } else if (pid == 0) {
      // first child
      setsid();

      if ((pid = fork()) < 0) {
        errorExit("fork error\n");
      } else if (pid > 0) {
        // exit first child
        close(client_socket);
        exit(0);
      }
      // second children
      accept_request(client_socket);
      exit(0);
    }

    // clean first child，make sure first child will not be a zombie process
    if (waitpid(pid, NULL, 0) != pid) {
      errorExit("waitpid error\n");
    }
    close(client_socket);
  }
  close(server_sock);
  return 0;
}