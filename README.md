About
===============
`ngx_pgcopy` is module that allows `nginx` to communicate directly with `PostgreSQL` database with [sql-COPY query](http://www.postgresql.org/docs/9.5/static/sql-copy.html).

Support 
- PUT and POST body loader.
- Direct transfer to/from database CSV, [JSON, XML](ttps://github.com/AntonRiab/slim_middle_samples).
- Supported "SELECT" inside in request "COPY TO".
- HTTP Authentication Basic is transparent to PostgreSQL database connection authentication.

Response is generated from COPY formats.


Status
===============
In develop.  
Work only with postgresql ip:port 127.0.0.1:5432.  
If you whant compile with debug, build it only on gcc, not clang.  

Tested on 
- ubuntu  14.04(nginx 1.13, postgresql 9.6)
- freebsd 10.3 (nginx 1.11.3, postgresql 9.3.12) without debug

For debugging or if you want to look to detailed log, configure it `--with-debug` before build. Or, if you want to debug log only for ngx_pgcopy, uncomment the top line in `ngx_http_pgcopy_module.c` with `#define PGCOPY_DEBUG 1`.

Installation
===============
Install to your system postgresql-9.6 with contrib, libpq develop version and pcre 8.3* develop version. After that run

        git clone https://github.com/nginx/nginx nginx
        cd nginx
        git clone https://github.com/AntonRiab/ngx_pgcopy ngx_pgcopy
        auto/configure --add-module=./ngx_pgcopy
        make
        make install

Configuration directives
===============
pgcopy_server
---------------
* **syntax** : `pgcopy_server name "ip[:port] dbname=dbname [user=user password=pass]" [Basic|none]`
* **default**: `none`
* **context**: `server, location, if location`

**Attention:** Set "Basic" only if you use connection string without user and password information.


pgcopy_query
---------------
* **syntax** : `pgcopy_query POST|PUT|GET pgcopy_server_name query_copy_from_stdin_or_to_stdout`
* **default**: `none`
* **context**: `location, if location`

**Attention:** If you whant to use it with nginx variable, you need to use "map" filter **to avoid injection**.  
Look at section "Sample configurations".


pgcopy_delay
---------------
* **syntax** : `pgcopy_delay time_in_ms`
* **default**: `100`
* **context**: `server, location, if location`

Delay before processing next buffer window.


client_body_buffer_size 
---------------
Core nginx variable, sets size of window between nginx and postgresql for one loop in nginx core.

Response
===============
Is generated from COPY formats.  

HTTP answers
- `200 OK` on GET request successfully
- `201 Created` on PUT|POST request data load **successfully**
- `400 Bad Request` on PUT|POST request data load **error**(bad format too)


Sample configurations
===============
Typical configuration.
-----------------------
    http {
        server {
            pgcopy_server db_prv "host=127.0.0.1 dbname=testdb" Basic;
            pgcopy_server db_pub "host=127.0.0.1 dbname=testdb user=testuser password=123";

            location /priv {
                pgcopy_query PUT db_prv "COPY test_input(num, txt) FROM STDIN 
                    WITH DELIMITER ';';";
                pgcopy_query GET db_prv "COPY test_input(num, txt) TO STDOUT
                    WITH DELIMITER ';';";
            }

            location /pub {
                pgcopy_query GET db_pub "COPY test_input(num, txt) TO STDOUT
                    WITH DELIMITER ';';";
            }
        }
    }


Sample configuration to avoid injection.
-----------------------
Sample to filter argument a1 from url like next "http://your_server/pub?a1=someparametr"

    http {
        map $args $filter_arg {
           "~a1=(?<tmp>[a-zA-Z0-9-]+)"    "$tmp";
        }

        server {
            pgcopy_server db_pub "host=127.0.0.1 dbname=testdb user=testuser password=123";

            location /pub_arg {
                pgcopy_query GET db_pub 
                    "COPY (select num, txt, '$filter_arg' from test_input) TO STDOUT 
                        WITH DELIMITER ';';";
            }
        }
    }

About direct load JSON and XML.
-----------------------
This is based on setting "**client_body_in_file_only** on" and nginx variable **$request_body_file**.
Advanced information about it you can found in project [slim_middle_samples](https://github.com/AntonRiab/slim_middle_samples).

Compatible information (Tested with)
-----------------------
- [lua-nginx-module](https://github.com/openresty/lua-nginx-module)  

| Directives          | Compatible  |
| ------------------- | ----------- |
| set_by_lua          | OK          |
| access_by_lua_block | OK          |

- [ngx_http_perl_module](http://search.cpan.org/~zzz/Nginx-Perl-1.8.1.10/src/http/modules/perl/Nginx.pm)

| Directives          | Compatible  |
| ------------------- | ----------- |
| perl_set            | OK          |
| access_handler      | Core dumped |

- [nginScript](https://www.nginx.com/blog/introduction-nginscript/)

| Directives          | Compatible  |
| ------------------- | ----------- |
| js_set              | OK          |

- [ngx_postgres](https://github.com/FRiCKLE/ngx_postgres)  
It does not work in one location with ngx_postgres because ngx_postgres discarding request body.  
  
Do not to use Content handler in script modules with ngx_pgcopy. Because they will can't act on ngx_pgcopy in that stage.

License
======
    This module is licensed under the BSD license.

    Copyright (c) 2015-2017, by Anton Riabchevskiy (AntonRiab) <riab765@gmail.com>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Other information
===============
This software includes also parts of the code from:
- `ngx_postgres` (copyrighted by **FRiCKLE Piotr Sikora**, **Xiaozhe Wang**, **Yichun Zhang**)
- `nginx`        (copyrighted by **Igor Sysoev**, **Nginx Inc** under BSD license)


See also
===============
- [slim_middle_samples](https://github.com/AntonRiab/slim_middle_samples)

- [nginx](https://github.com/nginx/nginx)
