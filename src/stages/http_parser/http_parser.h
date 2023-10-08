#ifndef _INCLUDE_HTTP_PARSER_H
#define _INCLUDE_HTTP_PARSER_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"
#include "../lib/nodejs/http_parser_utils.h"

#define TOY_REQUEST "GET / HTTP/1.1\r\n"
#define TOY_RESPONSE "HTTP/1.1 200 OK\r\n"

#define HTTP_PARSER_BUF_MAX_LEN 2048

static http_parser_settings settings =
  {.on_message_begin = NULL
  ,.on_header_field = NULL
  ,.on_header_value = NULL
  ,.on_url = NULL
  ,.on_status = NULL
  ,.on_body = NULL
  ,.on_headers_complete = NULL
  ,.on_message_complete = NULL
  ,.on_chunk_header = NULL
  ,.on_chunk_complete = NULL
  };

struct http_parser_state{
    http_parser req_parser;
    http_parser resp_parser;
};


#endif/* _INCLUDE_HTTP_PARSER_H */