/*
 * Copyright (C) 2025 The pgexporter community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgexporter */
#include <pgexporter.h>
#include <aes.h>
#include <bridge.h>
#include <configuration.h>
#include <ext_query_alts.h>
#include <logging.h>
#include <management.h>
#include <network.h>
#include <pg_query_alts.h>
#include <prometheus.h>
#include <security.h>
#include <shmem.h>
#include <utils.h>
#include <value.h>
#include <yaml_configuration.h>

/* system */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define LINE_LENGTH 512

static int extract_syskey_value(char* str, char** key, char** value);
static void extract_key_value(char* str, char** key, char** value);
static int as_int(char* str, int* i);
static int as_long(char* str, long* l);
static int as_bool(char* str, bool* b);
static int as_logging_type(char* str);
static int as_logging_level(char* str);
static int as_logging_mode(char* str);
static int as_hugepage(char* str);
static unsigned int as_update_process_title(char* str, unsigned int default_policy);
static int as_logging_rotation_size(char* str, size_t* size);
static int as_logging_rotation_age(char* str, int* age);
static int as_seconds(char* str, int* age, int default_age);
static int as_bytes(char* str, long* bytes, long default_bytes);
static int as_endpoints(char* str, struct configuration* config, bool reload);
static bool transfer_configuration(struct configuration* config, struct configuration* reload);
static void copy_server(struct server* dst, struct server* src);
static void copy_user(struct user* dst, struct user* src);
static void copy_promethus(struct prometheus* dst, struct prometheus* src);
static void copy_endpoint(struct endpoint* dst, struct endpoint* src);
static int restart_int(char* name, int e, int n);
static int restart_string(char* name, char* e, char* n);

static bool is_empty_string(char* s);
 static bool is_valid_config_key(const char* config_key, struct config_key_info* key_info);
static int apply_configuration(char* config_key, char* config_value, struct config_key_info* key_info, bool* restart_required);
static int apply_main_configuration(struct configuration* config, struct server* srv, char* section, char* key, char* value);
static int write_config_value(char* buffer, char* config_key, size_t buffer_size);

static void add_configuration_response(struct json* res);
static void add_servers_configuration_response(struct json* res);

/**
 *
 */
int
pgexporter_init_configuration(void* shm)
{
   struct configuration* config;

   config = (struct configuration*)shm;

   config->metrics = -1;
   config->cache = true;
   config->number_of_metric_names = 0;
   memset(config->metric_names, 0, sizeof(config->metric_names));

   config->bridge = -1;
   config->bridge_cache_max_age = 300;
   config->bridge_cache_max_size = PROMETHEUS_DEFAULT_BRIDGE_CACHE_SIZE;
   config->bridge_json = -1;
   config->bridge_json_cache_max_size = PROMETHEUS_DEFAULT_BRIDGE_JSON_CACHE_SIZE;

   memset(config->global_extensions, 0, MAX_EXTENSIONS_CONFIG_LENGTH);
   for (int i = 0; i < NUMBER_OF_SERVERS; i++)
   {
      memset(config->servers[i].extensions_config, 0, MAX_EXTENSIONS_CONFIG_LENGTH);
   }
   config->tls = false;

   config->blocking_timeout = 30;
   config->authentication_timeout = 5;

   config->keep_alive = true;
   config->nodelay = true;
   config->non_blocking = true;
   config->backlog = 16;
   config->hugepage = HUGEPAGE_TRY;

   config->update_process_title = UPDATE_PROCESS_TITLE_VERBOSE;

   config->log_type = PGEXPORTER_LOGGING_TYPE_CONSOLE;
   config->log_level = PGEXPORTER_LOGGING_LEVEL_INFO;
   config->log_mode = PGEXPORTER_LOGGING_MODE_APPEND;
   atomic_init(&config->log_lock, STATE_FREE);

   atomic_init(&config->logging_info, 0);
   atomic_init(&config->logging_warn, 0);
   atomic_init(&config->logging_error, 0);
   atomic_init(&config->logging_fatal, 0);

   for (int i = 0; i < NUMBER_OF_METRICS; i++)
   {
      config->prometheus[i].sort_type = SORT_NAME;
      config->prometheus[i].server_query_type = SERVER_QUERY_BOTH;
   }

   return 0;
}

/**
 *
 */
int
pgexporter_read_configuration(void* shm, char* filename)
{
   FILE* file;
   char section[LINE_LENGTH];
   char line[LINE_LENGTH];
   char* key = NULL;
   char* value = NULL;
   char* ptr = NULL;
   size_t max;
   int idx_server = 0;
   struct server srv;
   struct configuration* config;

   file = fopen(filename, "r");

   if (!file)
   {
      return 1;
   }

   memset(&section, 0, LINE_LENGTH);
   config = (struct configuration*)shm;

   while (fgets(line, sizeof(line), file))
   {
      if (!is_empty_string(line))
      {
         if (line[0] == '[')
         {
            ptr = strchr(line, ']');
            if (ptr)
            {
               memset(&section, 0, LINE_LENGTH);
               max = ptr - line - 1;
               if (max > MISC_LENGTH - 1)
               {
                  max = MISC_LENGTH - 1;
               }
               memcpy(&section, line + 1, max);
               if (strcmp(section, "pgexporter"))
               {
                  if (idx_server > 0 && idx_server <= NUMBER_OF_SERVERS)
                  {
                     for (int j = 0; j < idx_server - 1; j++)
                     {
                        if (!strcmp(srv.name, config->servers[j].name))
                        {
                           warnx("Duplicate server name \"%s\"", srv.name);
                           fclose(file);
                           exit(1);
                        }
                     }

                     memcpy(&(config->servers[idx_server - 1]), &srv, sizeof(struct server));
                  }
                  else if (idx_server > NUMBER_OF_SERVERS)
                  {
                     warnx("Maximum number of servers exceeded");
                  }

                  memset(&srv, 0, sizeof(struct server));
                  snprintf(&srv.name[0], MISC_LENGTH, "%s", section);
                  srv.fd = -1;
                  srv.state = SERVER_UNKNOWN;
                  srv.version = SERVER_UNDERTERMINED_VERSION;

                  idx_server++;
               }
            }
         }
         else if (line[0] == '#' || line[0] == ';')
         {
            /* Comment, so ignore */
         }
         else
         {
            if (pgexporter_starts_with(line, "unix_socket_dir") || pgexporter_starts_with(line, "metrics_path")
                || pgexporter_starts_with(line, "log_path") || pgexporter_starts_with(line, "tls_cert_file")
                || pgexporter_starts_with(line, "tls_key_file") || pgexporter_starts_with(line, "tls_ca_file")
                || pgexporter_starts_with(line, "metrics_cert_file") || pgexporter_starts_with(line, "metrics_key_file")
                || pgexporter_starts_with(line, "metrics_ca_file"))
            {
               extract_syskey_value(line, &key, &value);
            }
            else
            {
               extract_key_value(line, &key, &value);
            }

            if (key && value)
            {
               bool unknown = false;

               /* printf("|%s|%s|\n", key, value); */

               if (!strcmp(key, "host"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->host, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.host, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "port"))
               {
                  if (strlen(section) > 0)
                  {
                     if (as_int(value, &srv.port))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "user"))
               {
                  if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_USERNAME_LENGTH - 1)
                     {
                        max = MAX_USERNAME_LENGTH - 1;
                     }
                     memcpy(&srv.username, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->metrics))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_cache_max_size"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     long l = 0;
                     if (as_bytes(value, &l, 0))
                     {
                        unknown = true;
                     }

                     config->metrics_cache_max_size = (size_t)l;
                     if (config->metrics_cache_max_size > PROMETHEUS_MAX_CACHE_SIZE)
                     {
                        config->metrics_cache_max_size = PROMETHEUS_MAX_CACHE_SIZE;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_cache_max_age"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_seconds(value, &config->metrics_cache_max_age, 0))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->bridge))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge_endpoints"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_endpoints(value, config, false))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge_cache_max_size"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     long l = 0;

                     if (as_bytes(value, &l, PROMETHEUS_DEFAULT_BRIDGE_CACHE_SIZE))
                     {
                        unknown = true;
                     }

                     config->bridge_cache_max_size = (size_t)l;

                     if (config->bridge_cache_max_size > PROMETHEUS_MAX_BRIDGE_CACHE_SIZE)
                     {
                        config->bridge_cache_max_size = PROMETHEUS_MAX_BRIDGE_CACHE_SIZE;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge_cache_max_age"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_seconds(value, &config->bridge_cache_max_age, 300))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge_json"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->bridge_json))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "bridge_json_cache_max_size"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     long l = 0;

                     if (as_bytes(value, &l, PROMETHEUS_DEFAULT_BRIDGE_JSON_CACHE_SIZE))
                     {
                        unknown = true;
                     }

                     config->bridge_json_cache_max_size = (size_t)l;

                     if (config->bridge_json_cache_max_size > PROMETHEUS_MAX_BRIDGE_JSON_CACHE_SIZE)
                     {
                        config->bridge_json_cache_max_size = PROMETHEUS_MAX_BRIDGE_JSON_CACHE_SIZE;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "management"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->management))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "cache"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_bool(value, &config->cache))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "tls"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_bool(value, &config->tls))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "tls_ca_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->tls_ca_file, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.tls_ca_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "tls_cert_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->tls_cert_file, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.tls_cert_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "tls_key_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->tls_key_file, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(&srv.tls_key_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_ca_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->metrics_ca_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_cert_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->metrics_cert_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_key_file"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->metrics_key_file, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "blocking_timeout"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->blocking_timeout))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "pidfile"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->pidfile, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "update_process_title"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     config->update_process_title = as_update_process_title(value, UPDATE_PROCESS_TITLE_VERBOSE);
                  }
                  else
                  {
                     unknown = false;
                  }
               }
               else if (!strcmp(key, "log_type"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     config->log_type = as_logging_type(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_level"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     config->log_level = as_logging_level(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_path"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->log_path, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_rotation_size"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_logging_rotation_size(value, &config->log_rotation_size))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_rotation_age"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_logging_rotation_age(value, &config->log_rotation_age))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_line_prefix"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->log_line_prefix, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_mode"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     config->log_mode = as_logging_mode(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "unix_socket_dir"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->unix_socket_dir, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "libev"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->libev, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "keep_alive"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_bool(value, &config->keep_alive))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "nodelay"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_bool(value, &config->nodelay))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "non_blocking"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_bool(value, &config->non_blocking))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "backlog"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     if (as_int(value, &config->backlog))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "hugepage"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     config->hugepage = as_hugepage(value);

                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "data_dir"))
               {
                  if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.data, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "wal_dir"))
               {
                  if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.wal, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "metrics_path"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     max = strlen(value);
                     if (max > MAX_PATH - 1)
                     {
                        max = MAX_PATH - 1;
                     }
                     memcpy(config->metrics_path, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "extensions"))
               {
                  if (!strcmp(section, "pgexporter"))
                  {
                     // Store global extensions config
                     max = strlen(value);
                     if (max > MAX_EXTENSIONS_CONFIG_LENGTH - 1)
                     {
                        max = MAX_EXTENSIONS_CONFIG_LENGTH - 1;
                     }
                     memcpy(config->global_extensions, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     // Store server-specific extensions config
                     max = strlen(section);
                     if (max > MAX_EXTENSIONS_CONFIG_LENGTH - 1)
                     {
                        max = MAX_EXTENSIONS_CONFIG_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_EXTENSIONS_CONFIG_LENGTH - 1)
                     {
                        max = MAX_EXTENSIONS_CONFIG_LENGTH - 1;
                     }
                     memcpy(&srv.extensions_config, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else
               {
                  unknown = true;
               }

               if (unknown)
               {
                  warnx("Unknown: Section=%s, Key=%s, Value=%s", strlen(section) > 0 ? section : "<unknown>", key, value);
               }

               free(key);
               free(value);
               key = NULL;
               value = NULL;
            }
            else
            {
               warnx("Unknown: Section=%s, Line=%s", strlen(section) > 0 ? section : "<unknown>", line);

               free(key);
               free(value);
               key = NULL;
               value = NULL;
            }
         }
      }
   }

   if (strlen(srv.name) > 0)
   {

      for (int j = 0; j < idx_server - 1; j++)
      {
         if (!strcmp(srv.name, config->servers[j].name))
         {
            warnx("Duplicate server name \"%s\"", srv.name);
            fclose(file);
            exit(1);
         }
      }

      memcpy(&(config->servers[idx_server - 1]), &srv, sizeof(struct server));
   }

   config->number_of_servers = idx_server;
   fclose(file);

   return 0;
}

/**
 *
 */
int
pgexporter_validate_configuration(void* shm)
{
   struct stat st;
   struct configuration* config;

   config = (struct configuration*)shm;

   if (strlen(config->host) == 0)
   {
      pgexporter_log_fatal("pgexporter: No host defined");
      return 1;
   }

   if (strlen(config->unix_socket_dir) == 0)
   {
      pgexporter_log_fatal("pgexporter: No unix_socket_dir defined");
      return 1;
   }

   if (stat(config->unix_socket_dir, &st) == 0 && S_ISDIR(st.st_mode))
   {
      /* Ok */
   }
   else
   {
      pgexporter_log_fatal("pgexporter: unix_socket_dir is not a directory (%s)", config->unix_socket_dir);
      return 1;
   }

   if (config->metrics == -1 && config->bridge == -1)
   {
      pgexporter_log_fatal("pgexporter: No metrics nor bridge defined");
      return 1;
   }

   if (config->bridge == -1 && config->bridge_json != -1)
   {
      pgexporter_log_fatal("pgexporter: Bridge JSON defined, but bridge isn't enabled");
      return 1;
   }

   if (config->bridge_json != -1 && config->bridge_json_cache_max_size <= 0)
   {
      pgexporter_log_fatal("pgexporter: Bridge JSON requires a cache");
      return 1;
   }

   if (config->backlog < 16)
   {
      config->backlog = 16;
   }

   if (strlen(config->metrics_cert_file) > 0)
   {
      if (!pgexporter_exists(config->metrics_cert_file))
      {
         pgexporter_log_error("metrics cert file does not exist, falling back to plain HTTP");
         memset(config->metrics_cert_file, 0, sizeof(config->metrics_cert_file));
         memset(config->metrics_key_file, 0, sizeof(config->metrics_key_file));
         memset(config->metrics_ca_file, 0, sizeof(config->metrics_ca_file));
      }
   }

   if (strlen(config->metrics_key_file) > 0)
   {
      if (!pgexporter_exists(config->metrics_key_file))
      {
         pgexporter_log_error("metrics key file does not exist, falling back to plain HTTP");
         memset(config->metrics_cert_file, 0, sizeof(config->metrics_cert_file));
         memset(config->metrics_key_file, 0, sizeof(config->metrics_key_file));
         memset(config->metrics_ca_file, 0, sizeof(config->metrics_ca_file));
      }
   }

   if (strlen(config->metrics_ca_file) > 0)
   {
      if (!pgexporter_exists(config->metrics_ca_file))
      {
         pgexporter_log_error("metrics ca file does not exist, falling back to plain HTTP");
         memset(config->metrics_cert_file, 0, sizeof(config->metrics_cert_file));
         memset(config->metrics_key_file, 0, sizeof(config->metrics_key_file));
         memset(config->metrics_ca_file, 0, sizeof(config->metrics_ca_file));
      }
   }

   if (config->number_of_servers <= 0)
   {
      pgexporter_log_fatal("pgexporter: No servers defined");
      return 1;
   }

   for (int i = 0; i < config->number_of_servers; i++)
   {
      if (!strcmp(config->servers[i].name, "pgexporter"))
      {
         pgexporter_log_fatal("pgexporter: pgexporter is a reserved word for a host");
         return 1;
      }

      if (!strcmp(config->servers[i].name, "all"))
      {
         pgexporter_log_fatal("pgexporter: all is a reserved word for a host");
         return 1;
      }

      if (strlen(config->servers[i].host) == 0)
      {
         pgexporter_log_fatal("pgexporter: No host defined for %s", config->servers[i].name);
         return 1;
      }

      if (config->servers[i].port == 0)
      {
         pgexporter_log_fatal("pgexporter: No port defined for %s", config->servers[i].name);
         return 1;
      }

      if (strlen(config->servers[i].username) == 0)
      {
         pgexporter_log_fatal("pgexporter: No user defined for %s", config->servers[i].name);
         return 1;
      }
   }

   return 0;
}

/**
 *
 */
int
pgexporter_read_users_configuration(void* shm, char* filename)
{
   FILE* file;
   char line[LINE_LENGTH];
   int index;
   char* master_key = NULL;
   char* username = NULL;
   char* password = NULL;
   char* decoded = NULL;
   size_t decoded_length = 0;
   char* ptr = NULL;
   struct configuration* config;

   file = fopen(filename, "r");

   if (!file)
   {
      goto error;
   }

   if (pgexporter_get_master_key(&master_key))
   {
      goto masterkey;
   }

   index = 0;
   config = (struct configuration*)shm;

   while (fgets(line, sizeof(line), file))
   {
      if (!is_empty_string(line))
      {
         if (line[0] == '#' || line[0] == ';')
         {
            /* Comment, so ignore */
         }
         else
         {
            ptr = strtok(line, ":");

            username = ptr;

            ptr = strtok(NULL, ":");

            if (ptr == NULL)
            {
               goto error;
            }

            if (pgexporter_base64_decode(ptr, strlen(ptr), (void**)&decoded, &decoded_length))
            {
               goto error;
            }

            if (pgexporter_decrypt(decoded, decoded_length, master_key, &password, ENCRYPTION_AES_256_CBC))
            {
               goto error;
            }

            if (strlen(username) < MAX_USERNAME_LENGTH &&
                strlen(password) < MAX_PASSWORD_LENGTH)
            {
               snprintf(&config->users[index].username[0], MAX_USERNAME_LENGTH, "%s", username);
               snprintf(&config->users[index].password[0], MAX_PASSWORD_LENGTH, "%s", password);
            }
            else
            {
               warnx("pgexporter: Invalid USER entry");
               warnx("%s\n", line);
            }

            free(password);
            free(decoded);

            password = NULL;
            decoded = NULL;

            index++;
         }
      }
   }

   config->number_of_users = index;

   if (config->number_of_users > NUMBER_OF_USERS)
   {
      goto above;
   }

   free(master_key);

   fclose(file);

   return 0;

error:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 1;

masterkey:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 2;

above:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 3;
}

/**
 *
 */
int
pgexporter_validate_users_configuration(void* shm)
{
   struct configuration* config;

   config = (struct configuration*)shm;

   if (config->number_of_users <= 0)
   {
      pgexporter_log_fatal("pgexporter: No users defined");
      return 1;
   }

   for (int i = 0; i < config->number_of_servers; i++)
   {
      bool found = false;

      for (int j = 0; !found && j < config->number_of_users; j++)
      {
         if (!strcmp(config->servers[i].username, config->users[j].username))
         {
            found = true;
         }
      }

      if (!found)
      {
         pgexporter_log_fatal("pgexporter: Unknown user (\'%s\') defined for %s", config->servers[i].username, config->servers[i].name);
         return 1;
      }
   }

   return 0;
}

/**
 *
 */
int
pgexporter_read_admins_configuration(void* shm, char* filename)
{
   FILE* file;
   char line[LINE_LENGTH];
   int index;
   char* master_key = NULL;
   char* username = NULL;
   char* password = NULL;
   char* decoded = NULL;
   size_t decoded_length = 0;
   char* ptr = NULL;
   struct configuration* config;

   file = fopen(filename, "r");

   if (!file)
   {
      goto error;
   }

   if (pgexporter_get_master_key(&master_key))
   {
      goto masterkey;
   }

   index = 0;
   config = (struct configuration*)shm;

   while (fgets(line, sizeof(line), file))
   {
      if (!is_empty_string(line))
      {
         if (line[0] == '#' || line[0] == ';')
         {
            /* Comment, so ignore */
         }
         else
         {
            ptr = strtok(line, ":");

            username = ptr;

            ptr = strtok(NULL, ":");

            if (ptr == NULL)
            {
               goto error;
            }

            if (pgexporter_base64_decode(ptr, strlen(ptr), (void**)&decoded, &decoded_length))
            {
               goto error;
            }

            if (pgexporter_decrypt(decoded, decoded_length, master_key, &password, ENCRYPTION_AES_256_CBC))
            {
               goto error;
            }

            if (strlen(username) < MAX_USERNAME_LENGTH &&
                strlen(password) < MAX_PASSWORD_LENGTH)
            {
               snprintf(&config->admins[index].username[0], MAX_USERNAME_LENGTH, "%s", username);
               snprintf(&config->admins[index].password[0], MAX_PASSWORD_LENGTH, "%s", password);
            }
            else
            {
               warnx("pgexporter: Invalid ADMIN entry");
               warnx("%s", line);
            }

            free(password);
            free(decoded);

            password = NULL;
            decoded = NULL;

            index++;
         }
      }
   }

   config->number_of_admins = index;

   if (config->number_of_admins > NUMBER_OF_ADMINS)
   {
      goto above;
   }

   free(master_key);

   fclose(file);

   return 0;

error:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 1;

masterkey:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 2;

above:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 3;
}

/**
 *
 */
int
pgexporter_validate_admins_configuration(void* shm)
{
   struct configuration* config;

   config = (struct configuration*)shm;

   if (config->management > 0 && config->number_of_admins == 0)
   {
      pgexporter_log_warn("pgexporter: Remote management enabled, but no admins are defined");
   }
   else if (config->management == 0 && config->number_of_admins > 0)
   {
      pgexporter_log_warn("pgexporter: Remote management disabled, but admins are defined");
   }

   return 0;
}

int
pgexporter_reload_configuration(bool* r)
{
   size_t reload_size;
   struct configuration* reload = NULL;
   struct configuration* config;

   config = (struct configuration*)shmem;

   *r = false;

   pgexporter_log_trace("Configuration: %s", config->configuration_path);
   pgexporter_log_trace("Users: %s", config->users_path);
   pgexporter_log_trace("Admins: %s", config->admins_path);

   reload_size = sizeof(struct configuration);

   if (pgexporter_create_shared_memory(reload_size, HUGEPAGE_OFF, (void**)&reload))
   {
      goto error;
   }

   pgexporter_init_configuration((void*)reload);

   if (pgexporter_read_configuration((void*)reload, config->configuration_path))
   {
      goto error;
   }

   if (pgexporter_read_users_configuration((void*)reload, config->users_path))
   {
      goto error;
   }

   if (strcmp("", config->admins_path))
   {
      if (pgexporter_read_admins_configuration((void*)reload, config->admins_path))
      {
         goto error;
      }
   }

   if (pgexporter_read_internal_yaml_metrics(reload, true))
   {
      goto error;
   }

   if (strlen(reload->metrics_path) > 0)
   {
      if (pgexporter_read_metrics_configuration((void*)reload))
      {
         goto error;
      }
   }

   if (pgexporter_validate_configuration(reload))
   {
      goto error;
   }

   if (pgexporter_validate_users_configuration(reload))
   {
      goto error;
   }

   if (pgexporter_validate_admins_configuration(reload))
   {
      goto error;
   }

   *r = transfer_configuration(config, reload);

   /* Free Old Query Alts AVL Tree */
   for (int i = 0; reload != NULL && i < reload->number_of_metrics; i++)
   {
      pgexporter_free_pg_query_alts(reload);
   }
   pgexporter_free_extension_query_alts(reload);

   pgexporter_destroy_shared_memory((void*)reload, reload_size);

   pgexporter_log_debug("Reload: Success");

   return 0;

error:

   /* Free Old Query Alts AVL Tree */
   for (int i = 0; reload != NULL && i < reload->number_of_metrics; i++)
   {
      pgexporter_free_pg_query_alts(reload);
   }
   pgexporter_free_extension_query_alts(reload);

   pgexporter_destroy_shared_memory((void*)reload, reload_size);

   pgexporter_log_debug("Reload: Failure");

   return 1;
}

void
pgexporter_conf_get(SSL* ssl __attribute__((unused)), int client_fd, uint8_t compression, uint8_t encryption, struct json* payload)
{
   struct json* response = NULL;
   char* elapsed = NULL;
   time_t start_time;
   time_t end_time;
   int total_seconds;

   pgexporter_start_logging();

   start_time = time(NULL);

   if (pgexporter_management_create_response(payload, -1, &response))
   {
      pgexporter_management_response_error(NULL, client_fd, NULL, MANAGEMENT_ERROR_CONF_GET_ERROR, compression, encryption, payload);
      pgexporter_log_error("Conf Get: Error creating json object (%d)", MANAGEMENT_ERROR_CONF_GET_ERROR);
      goto error;
   }

   add_configuration_response(response);
   add_servers_configuration_response(response);

   end_time = time(NULL);

   if (pgexporter_management_response_ok(NULL, client_fd, start_time, end_time, compression, encryption, payload))
   {
      pgexporter_management_response_error(NULL, client_fd, NULL, MANAGEMENT_ERROR_CONF_GET_NETWORK, compression, encryption, payload);
      pgexporter_log_error("Conf Get: Error sending response");

      goto error;
   }

   elapsed = pgexporter_get_timestamp_string(start_time, end_time, &total_seconds);

   pgexporter_log_info("Conf Get (Elapsed: %s)", elapsed);

   pgexporter_json_destroy(payload);

   pgexporter_disconnect(client_fd);

   pgexporter_stop_logging();

   exit(0);
error:

   pgexporter_json_destroy(payload);

   pgexporter_disconnect(client_fd);

   pgexporter_stop_logging();

   exit(1);

}

int
pgexporter_conf_set(SSL* ssl, int client_fd, uint8_t compression, uint8_t encryption, struct json* payload, bool* restart_required)
{
   char* en = NULL;
   int ec = -1;
   struct json* response = NULL;
   struct json* request = NULL;
   char* config_key = NULL;
   char* config_value = NULL;
   char* elapsed = NULL;
   time_t start_time;
   time_t end_time;
   int32_t total_seconds;
   char old_value[MISC_LENGTH];
   char new_value[MISC_LENGTH];
   struct config_key_info key_info;

   pgexporter_start_logging();

   start_time = time(NULL);

   *restart_required = false;

   // Extract config_key and config_value from request
   request = (struct json*)pgexporter_json_get(payload, MANAGEMENT_CATEGORY_REQUEST);
   if (!request)
   {
      ec = MANAGEMENT_ERROR_CONF_SET_NOREQUEST;
      pgexporter_log_error("Conf Set: No request category found in payload (%d)", MANAGEMENT_ERROR_CONF_SET_NOREQUEST);
      goto error;
   }

   config_key = (char*)pgexporter_json_get(request, MANAGEMENT_ARGUMENT_CONFIG_KEY);
   config_value = (char*)pgexporter_json_get(request, MANAGEMENT_ARGUMENT_CONFIG_VALUE);

   if (!config_key || !config_value)
   {
      ec = MANAGEMENT_ERROR_CONF_SET_NOCONFIG_KEY_OR_VALUE;
      pgexporter_log_error("Conf Set: No config key or config value in request (%d)", MANAGEMENT_ERROR_CONF_SET_NOCONFIG_KEY_OR_VALUE);
      goto error;
   }

   if (!is_valid_config_key(config_key, &key_info))
   {
      ec = MANAGEMENT_ERROR_CONF_SET_ERROR;
      pgexporter_log_error("Conf Set: Invalid config key format: %s", config_key);
      goto error;
   }

   // Get old value before applying changes
   memset(old_value, 0, MISC_LENGTH);
   if (write_config_value(old_value, config_key, MISC_LENGTH))
   {
      snprintf(old_value, MISC_LENGTH, "<unknown>");
   }

   // Apply configuration change
   if (apply_configuration(config_key, config_value, &key_info, restart_required))
   {
      ec = MANAGEMENT_ERROR_CONF_SET_ERROR;
      pgexporter_log_error("Conf Set: Failed to apply configuration change %s=%s", config_key, config_value);
      goto error;
   }

   // Create response
   if (pgexporter_management_create_response(payload, -1, &response))
   {
      ec = MANAGEMENT_ERROR_CONF_SET_ERROR;
      pgexporter_log_error("Conf Set: Error creating json object (%d)", MANAGEMENT_ERROR_CONF_SET_ERROR);
      goto error;
   }

   // Get new value after applying changes
   memset(new_value, 0, MISC_LENGTH);
   if (write_config_value(new_value, config_key, MISC_LENGTH))
   {
      snprintf(new_value, MISC_LENGTH, "<unknown>");
   }

   if (*restart_required)
   {
      // Restart required - configuration not applied
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_STATUS, (uintptr_t)CONFIGURATION_STATUS_RESTART_REQUIRED, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_MESSAGE, (uintptr_t)CONFIGURATION_MESSAGE_RESTART_REQUIRED, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_CONFIG_KEY, (uintptr_t)config_key, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_REQUESTED_VALUE, (uintptr_t)config_value, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_CURRENT_VALUE, (uintptr_t)old_value, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_RESTART_REQUIRED, (uintptr_t)true, ValueBool);
      pgexporter_log_info("Conf Set: Restart required for %s=%s. Current value: %s", config_key, config_value, old_value);
   }
   else
   {
      // Success - configuration applied
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_STATUS, (uintptr_t)CONFIGURATION_STATUS_SUCCESS, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_MESSAGE, (uintptr_t)CONFIGURATION_MESSAGE_SUCCESS, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_CONFIG_KEY, (uintptr_t)config_key, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_OLD_VALUE, (uintptr_t)old_value, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_NEW_VALUE, (uintptr_t)new_value, ValueString);
      pgexporter_json_put(response, CONFIGURATION_RESPONSE_RESTART_REQUIRED, (uintptr_t)false, ValueBool);
      pgexporter_log_info("Conf Set: Successfully applied %s: %s -> %s", config_key, old_value, new_value);
   }

   end_time = time(NULL);

   if (pgexporter_management_response_ok(ssl, client_fd, start_time, end_time, compression, encryption, payload))
   {
      ec = MANAGEMENT_ERROR_CONF_SET_NETWORK;
      pgexporter_log_error("Conf Set: Error sending response");
      goto error;
   }

   elapsed = pgexporter_get_timestamp_string(start_time, end_time, &total_seconds);
   pgexporter_log_info("Conf Set (Elapsed: %s)", elapsed);

   if (elapsed)
   {
      free(elapsed);
      elapsed = NULL;
   }

   pgexporter_json_destroy(payload);
   pgexporter_disconnect(client_fd);
   pgexporter_stop_logging();
   pgexporter_log_info("Configuration set operation completed successfully");
   return 0;

error:
   pgexporter_management_response_error(ssl, client_fd, en != NULL ? en : "pgexporter", ec != -1 ? ec : MANAGEMENT_ERROR_CONF_SET_ERROR, compression, encryption, payload);
   if (elapsed)
   {
      free(elapsed);
   }
   pgexporter_json_destroy(payload);
   pgexporter_disconnect(client_fd);
   pgexporter_stop_logging();
   pgexporter_log_error("Configuration set operation failed with error code: %d", ec != -1 ? ec : MANAGEMENT_ERROR_CONF_SET_ERROR);
   pgexporter_log_error("Configuration change failed, not applying changes");
   return 1;
}

static void
add_configuration_response(struct json* res)
{
   char* data = NULL;
   struct configuration* config = NULL;

   config = (struct configuration*)shmem;
   // JSON of main configuration
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_HOST, (uintptr_t)config->host, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_UNIX_SOCKET_DIR, (uintptr_t)config->unix_socket_dir, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS, (uintptr_t)config->metrics, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_PATH, (uintptr_t)config->metrics_path, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_AGE, (uintptr_t)config->metrics_cache_max_age, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_SIZE, (uintptr_t)config->metrics_cache_max_size, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE, (uintptr_t)config->bridge, ValueInt64);

   if (config->number_of_endpoints > 0)
   {
      for (int i = 0; i < config->number_of_endpoints; i++)
      {
         data = pgexporter_append(data, config->endpoints[i].host);
         data = pgexporter_append_char(data, ':');
         data = pgexporter_append_int(data, config->endpoints[i].port);

         if (i < config->number_of_endpoints - 1)
         {
            data = pgexporter_append_char(data, ',');
         }
      }
   }
   else
   {
      data = pgexporter_append(data, "");
   }

   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE_ENDPOINTS, (uintptr_t)data, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_AGE, (uintptr_t)config->bridge_cache_max_age, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_SIZE, (uintptr_t)config->bridge_cache_max_size, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE_JSON, (uintptr_t)config->bridge_json, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BRIDGE_JSON_CACHE_MAX_SIZE, (uintptr_t)config->bridge_json_cache_max_size, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_MANAGEMENT, (uintptr_t)config->management, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_CACHE, (uintptr_t)config->cache, ValueBool);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_TYPE, (uintptr_t)config->log_type, ValueInt32);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_LEVEL, (uintptr_t)config->log_level, ValueInt32);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_PATH, (uintptr_t)config->log_path, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_ROTATION_AGE, (uintptr_t)config->log_rotation_age, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_ROTATION_SIZE, (uintptr_t)config->log_rotation_size, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_LINE_PREFIX, (uintptr_t)config->log_line_prefix, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LOG_MODE, (uintptr_t)config->log_mode, ValueInt32);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BLOCKING_TIMEOUT, (uintptr_t)config->blocking_timeout, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_TLS, (uintptr_t)config->tls, ValueBool);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_TLS_CERT_FILE, (uintptr_t)config->tls_cert_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_TLS_CA_FILE, (uintptr_t)config->tls_ca_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_TLS_KEY_FILE, (uintptr_t)config->tls_key_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_CERT_FILE, (uintptr_t)config->metrics_cert_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_CA_FILE, (uintptr_t)config->metrics_ca_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_METRICS_KEY_FILE, (uintptr_t)config->metrics_key_file, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_LIBEV, (uintptr_t)config->libev, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_KEEP_ALIVE, (uintptr_t)config->keep_alive, ValueBool);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_NODELAY, (uintptr_t)config->nodelay, ValueBool);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_NON_BLOCKING, (uintptr_t)config->non_blocking, ValueBool);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_BACKLOG, (uintptr_t)config->backlog, ValueInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_HUGEPAGE, (uintptr_t)config->hugepage, ValueChar);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_PIDFILE, (uintptr_t)config->pidfile, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_UPDATE_PROCESS_TITLE, (uintptr_t)config->update_process_title, ValueUInt64);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_MAIN_CONF_PATH, (uintptr_t)config->configuration_path, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_USER_CONF_PATH, (uintptr_t)config->users_path, ValueString);
   pgexporter_json_put(res, CONFIGURATION_ARGUMENT_ADMIN_CONF_PATH, (uintptr_t)config->admins_path, ValueString);

   free(data);
}

static void
add_servers_configuration_response(struct json* res)
{
   struct configuration* config = (struct configuration*)shmem;
   struct json* server_section = NULL;
   struct json* server_conf = NULL;

   // Create a server section to hold all server configurations
   if (pgexporter_json_create(&server_section))
   {
      pgexporter_log_error("Failed to create server section JSON");
      goto error;
   }

   for (int i = 0; i < config->number_of_servers; i++)
   {
      if (pgexporter_json_create(&server_conf))
      {
         pgexporter_log_error("Failed to create server configuration JSON for %s",
                              config->servers[i].name);
         goto error;
      }

      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_HOST, (uintptr_t)config->servers[i].host, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_PORT, (uintptr_t)config->servers[i].port, ValueInt64);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_TLS_CERT_FILE, (uintptr_t)config->servers[i].tls_cert_file, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_TLS_KEY_FILE, (uintptr_t)config->servers[i].tls_key_file, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_TLS_CA_FILE, (uintptr_t)config->servers[i].tls_ca_file, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_USER, (uintptr_t)config->servers[i].username, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_DATA_DIR, (uintptr_t)config->servers[i].data, ValueString);
      pgexporter_json_put(server_conf, CONFIGURATION_ARGUMENT_WAL_DIR, (uintptr_t)config->servers[i].wal, ValueString);

      // Add this server to the server section using server name as key
      pgexporter_json_put(server_section, config->servers[i].name, (uintptr_t)server_conf, ValueJSON);
      server_conf = NULL; // Prevent double free
   }

   // Add the server section to the main response
   pgexporter_json_put(res, "server", (uintptr_t)server_section, ValueJSON);
   return;

error:
   pgexporter_json_destroy(server_conf);
   pgexporter_json_destroy(server_section);
   return;
}

static void
extract_key_value(char* str, char** key, char** value)
{
   char* equal = NULL;
   char* end = NULL;
   char* ptr = NULL;
   char left[MISC_LENGTH];
   char right[MISC_LENGTH];
   bool start_left = false;
   bool start_right = false;
   int idx = 0;
   int i = 0;
   char c = 0;
   char* k = NULL;
   char* v = NULL;

   *key = NULL;
   *value = NULL;

   equal = strchr(str, '=');

   if (equal != NULL)
   {
      memset(&left[0], 0, sizeof(left));
      memset(&right[0], 0, sizeof(right));

      i = 0;
      while (true)
      {
         ptr = str + i;
         if (ptr != equal)
         {
            c = *(str + i);
            if (c == '\t' || c == ' ' || c == '\"' || c == '\'')
            {
               /* Skip */
            }
            else
            {
               start_left = true;
            }

            if (start_left)
            {
               left[idx] = c;
               idx++;
            }
         }
         else
         {
            break;
         }
         i++;
      }

      end = strchr(str, '\n');
      idx = 0;

      for (size_t i = 0; i < strlen(equal); i++)
      {
         ptr = equal + i;
         if (ptr != end)
         {
            c = *(ptr);
            if (c == '=' || c == ' ' || c == '\t' || c == '\"' || c == '\'')
            {
               /* Skip */
            }
            else
            {
               start_right = true;
            }

            if (start_right)
            {
               if (c != '#')
               {
                  right[idx] = c;
                  idx++;
               }
               else
               {
                  break;
               }
            }
         }
         else
         {
            break;
         }
      }

      for (int i = strlen(left); i >= 0; i--)
      {
         if (left[i] == '\t' || left[i] == ' ' || left[i] == '\0' || left[i] == '\"' || left[i] == '\'')
         {
            left[i] = '\0';
         }
         else
         {
            break;
         }
      }

      for (int i = strlen(right); i >= 0; i--)
      {
         if (right[i] == '\t' || right[i] == ' ' || right[i] == '\0' || right[i] == '\r' || right[i] == '\"' || right[i] == '\'')
         {
            right[i] = '\0';
         }
         else
         {
            break;
         }
      }

      k = calloc(1, strlen(left) + 1);
      v = calloc(1, strlen(right) + 1);

      snprintf(k, strlen(left) + 1, "%s", left);
      snprintf(v, strlen(right) + 1, "%s", right);

      *key = k;
      *value = v;
   }
}

/**
 * Given a line of text extracts the key part and the value
 * and expands environment variables in the value (like $HOME).
 * Valid lines must have the form <key> = <value>.
 *
 * The key must be unquoted and cannot have any spaces
 * in front of it.
 *
 * The value will be extracted as it is without trailing and leading spaces.
 *
 * Comments on the right side of a value are allowed.
 *
 * Example of valid lines are:
 * <code>
 * foo = bar
 * foo=bar
 * foo=  bar
 * foo = "bar"
 * foo = 'bar'
 * foo = "#bar"
 * foo = '#bar'
 * foo = bar # bar set!
 * foo = bar# bar set!
 * </code>
 *
 * @param str the line of text incoming from the configuration file
 * @param key the pointer to where to store the key extracted from the line
 * @param value the pointer to where to store the value (as it is)
 * @returns 1 if unable to parse the line, 0 if everything is ok
 */
static int
extract_syskey_value(char* str, char** key, char** value)
{
   int c = 0;
   int offset = 0;
   int length = strlen(str);
   int d = length - 1;
   char* k = NULL;
   char* v = NULL;

   // the key does not allow spaces and is whatever is
   // on the left of the '='
   while (str[c] != ' ' && str[c] != '=' && c < length)
   {
      c++;
   }

   if (c >= length)
   {
      goto error;
   }

   for (int i = 0; i < c; i++)
   {
      k = pgexporter_append_char(k, str[i]);
   }

   while (c < length && (str[c] == ' ' || str[c] == '\t' || str[c] == '=' || str[c] == '\r' || str[c] == '\n'))
   {
      c++;
   }

   if (c == length)
   {
      v = calloc(1, 1); // empty string
      *key = k;
      *value = v;
      return 0;
   }

   offset = c;

   while ((str[d] == ' ' || str[d] == '\t' || str[d] == '\r' || str[d] == '\n') && d > c)
   {
      d--;
   }

   for (int i = offset; i <= d; i++)
   {
      v = pgexporter_append_char(v, str[i]);
   }

   char* resolved_path = NULL;

   if (pgexporter_resolve_path(v, &resolved_path))
   {
      free(k);
      free(v);
      free(resolved_path);
      k = NULL;
      v = NULL;
      resolved_path = NULL;
      goto error;
   }

   free(v);
   v = resolved_path;

   *key = k;
   *value = v;
   return 0;

error:
   return 1;
}

static int
as_int(char* str, int* i)
{
   char* endptr;
   long val;

   errno = 0;
   val = strtol(str, &endptr, 10);

   if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0))
   {
      goto error;
   }

   if (str == endptr)
   {
      goto error;
   }

   if (*endptr != '\0')
   {
      goto error;
   }

   *i = (int)val;

   return 0;

error:

   errno = 0;

   return 1;
}

static int
as_long(char* str, long* l)
{
   char* endptr;
   long val;

   errno = 0;
   val = strtol(str, &endptr, 10);

   if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
       (errno != 0 && val == 0))
   {
      goto error;
   }

   if (str == endptr)
   {
      goto error;
   }

   if (*endptr != '\0')
   {
      goto error;
   }

   *l = val;

   return 0;

error:

   errno = 0;

   return 1;
}

static int
as_bool(char* str, bool* b)
{
   if (!strcasecmp(str, "true") || !strcasecmp(str, "on") || !strcasecmp(str, "yes") || !strcasecmp(str, "1"))
   {
      *b = true;
      return 0;
   }

   if (!strcasecmp(str, "false") || !strcasecmp(str, "off") || !strcasecmp(str, "no") || !strcasecmp(str, "0"))
   {
      *b = false;
      return 0;
   }

   return 1;
}

static int
as_logging_type(char* str)
{
   if (!strcasecmp(str, "console"))
   {
      return PGEXPORTER_LOGGING_TYPE_CONSOLE;
   }

   if (!strcasecmp(str, "file"))
   {
      return PGEXPORTER_LOGGING_TYPE_FILE;
   }

   if (!strcasecmp(str, "syslog"))
   {
      return PGEXPORTER_LOGGING_TYPE_SYSLOG;
   }

   return 0;
}

static int
as_logging_level(char* str)
{
   size_t size = 0;
   int debug_level = 1;
   char* debug_value = NULL;

   if (!strncasecmp(str, "debug", strlen("debug")))
   {
      if (strlen(str) > strlen("debug"))
      {
         size = strlen(str) - strlen("debug");
         debug_value = (char*)malloc(size + 1);
         memset(debug_value, 0, size + 1);
         memcpy(debug_value, str + 5, size);
         if (as_int(debug_value, &debug_level))
         {
            // cannot parse, set it to 1
            debug_level = 1;
         }
         free(debug_value);
      }

      if (debug_level <= 1)
      {
         return PGEXPORTER_LOGGING_LEVEL_DEBUG1;
      }
      else if (debug_level == 2)
      {
         return PGEXPORTER_LOGGING_LEVEL_DEBUG2;
      }
      else if (debug_level == 3)
      {
         return PGEXPORTER_LOGGING_LEVEL_DEBUG3;
      }
      else if (debug_level == 4)
      {
         return PGEXPORTER_LOGGING_LEVEL_DEBUG4;
      }
      else if (debug_level >= 5)
      {
         return PGEXPORTER_LOGGING_LEVEL_DEBUG5;
      }
   }

   if (!strcasecmp(str, "info"))
   {
      return PGEXPORTER_LOGGING_LEVEL_INFO;
   }

   if (!strcasecmp(str, "warn"))
   {
      return PGEXPORTER_LOGGING_LEVEL_WARN;
   }

   if (!strcasecmp(str, "error"))
   {
      return PGEXPORTER_LOGGING_LEVEL_ERROR;
   }

   if (!strcasecmp(str, "fatal"))
   {
      return PGEXPORTER_LOGGING_LEVEL_FATAL;
   }

   return PGEXPORTER_LOGGING_LEVEL_INFO;
}

static int
as_logging_mode(char* str)
{
   if (!strcasecmp(str, "a") || !strcasecmp(str, "append"))
   {
      return PGEXPORTER_LOGGING_MODE_APPEND;
   }

   if (!strcasecmp(str, "c") || !strcasecmp(str, "create"))
   {
      return PGEXPORTER_LOGGING_MODE_CREATE;
   }

   return PGEXPORTER_LOGGING_MODE_APPEND;
}

static int
as_hugepage(char* str)
{
   if (!strcasecmp(str, "off"))
   {
      return HUGEPAGE_OFF;
   }

   if (!strcasecmp(str, "try"))
   {
      return HUGEPAGE_TRY;
   }

   if (!strcasecmp(str, "on"))
   {
      return HUGEPAGE_ON;
   }

   return HUGEPAGE_OFF;
}

/**
 * Utility function to understand the setting for updating
 * the process title.
 *
 * @param str the value obtained by the configuration parsing
 * @param default_policy a value to set when the configuration cannot be
 * understood
 *
 * @return The policy
 */
static unsigned int
as_update_process_title(char* str, unsigned int default_policy)
{
   if (is_empty_string(str))
   {
      return default_policy;
   }

   if (!strncmp(str, "never", MISC_LENGTH) || !strncmp(str, "off", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_NEVER;
   }
   else if (!strncmp(str, "strict", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_STRICT;
   }
   else if (!strncmp(str, "minimal", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_MINIMAL;
   }
   else if (!strncmp(str, "verbose", MISC_LENGTH) || !strncmp(str, "full", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_VERBOSE;
   }

   // not a valid setting
   return default_policy;
}

/**
 * Parses a string to see if it contains
 * a valid value for log rotation size.
 * Returns 0 if parsing ok, 1 otherwise.
 *
 */
static int
as_logging_rotation_size(char* str, size_t* size)
{
   long l = 0;
   int ret;

   ret = as_bytes(str, &l, PGEXPORTER_LOGGING_ROTATION_DISABLED);

   *size = (size_t)l;

   return ret;
}

/**
 * Parses the log_rotation_age string.
 * The string accepts
 * - s for seconds
 * - m for minutes
 * - h for hours
 * - d for days
 * - w for weeks
 *
 * The default is expressed in seconds.
 * The function sets the number of rotationg age as minutes.
 * Returns 1 for errors, 0 for correct parsing.
 *
 */
static int
as_logging_rotation_age(char* str, int* age)
{
   return as_seconds(str, age, PGEXPORTER_LOGGING_ROTATION_DISABLED);
}

/**
 * Parses an age string, providing the resulting value as seconds.
 * An age string is expressed by a number and a suffix that indicates
 * the multiplier. Accepted suffixes, case insensitive, are:
 * - s for seconds
 * - m for minutes
 * - h for hours
 * - d for days
 * - w for weeks
 *
 * The default is expressed in seconds.
 *
 * @param str the value to parse as retrieved from the configuration
 * @param age a pointer to the value that is going to store
 *        the resulting number of seconds
 * @param default_age a value to set when the parsing is unsuccesful

 */
static int
as_seconds(char* str, int* age, int default_age)
{
   int multiplier = 1;
   int index;
   char value[MISC_LENGTH];
   bool multiplier_set = false;
   int i_value = default_age;

   if (is_empty_string(str))
   {
      *age = default_age;
      return 0;
   }

   index = 0;
   for (size_t i = 0; i < strlen(str); i++)
   {
      if (isdigit(str[i]))
      {
         value[index++] = str[i];
      }
      else if (isalpha(str[i]) && multiplier_set)
      {
         // another extra char not allowed
         goto error;
      }
      else if (isalpha(str[i]) && !multiplier_set)
      {
         if (str[i] == 's' || str[i] == 'S')
         {
            multiplier = 1;
            multiplier_set = true;
         }
         else if (str[i] == 'm' || str[i] == 'M')
         {
            multiplier = 60;
            multiplier_set = true;
         }
         else if (str[i] == 'h' || str[i] == 'H')
         {
            multiplier = 3600;
            multiplier_set = true;
         }
         else if (str[i] == 'd' || str[i] == 'D')
         {
            multiplier = 24 * 3600;
            multiplier_set = true;
         }
         else if (str[i] == 'w' || str[i] == 'W')
         {
            multiplier = 24 * 3600 * 7;
            multiplier_set = true;
         }
      }
      else
      {
         // do not allow alien chars
         goto error;
      }
   }

   value[index] = '\0';
   if (!as_int(value, &i_value))
   {
      // sanity check: the value
      // must be a positive number!
      if (i_value >= 0)
      {
         *age = i_value * multiplier;
      }
      else
      {
         goto error;
      }

      return 0;
   }
   else
   {
error:
      *age = default_age;
      return 1;
   }
}

/**
 * Converts a "size string" into the number of bytes.
 *
 * Valid strings have one of the suffixes:
 * - b for bytes (default)
 * - k for kilobytes
 * - m for megabytes
 * - g for gigabytes
 *
 * The default is expressed always as bytes.
 * Uppercase letters work too.
 * If no suffix is specified, the value is expressed as bytes.
 *
 * @param str the string to parse (e.g., "2M")
 * @param bytes the value to set as result of the parsing stage
 * @param default_bytes the default value to set when the parsing cannot proceed
 * @return 1 if parsing is unable to understand the string, 0 is parsing is
 *         performed correctly (or almost correctly, e.g., empty string)
 */
static int
as_bytes(char* str, long* bytes, long default_bytes)
{
   int multiplier = 1;
   int index;
   char value[MISC_LENGTH];
   bool multiplier_set = false;
   long l_value = default_bytes;

   if (is_empty_string(str))
   {
      *bytes = default_bytes;
      return 0;
   }

   index = 0;
   for (size_t i = 0; i < strlen(str); i++)
   {
      if (isdigit(str[i]))
      {
         value[index++] = str[i];
      }
      else if (isalpha(str[i]) && multiplier_set)
      {
         // allow a 'B' suffix on a multiplier
         // like for instance 'MB', but don't allow it
         // for bytes themselves ('BB')
         if (multiplier == 1
             || (str[i] != 'b' && str[i] != 'B'))
         {
            // another non-digit char not allowed
            goto error;
         }
      }
      else if (isalpha(str[i]) && !multiplier_set)
      {
         if (str[i] == 'M' || str[i] == 'm')
         {
            multiplier = 1024 * 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'G' || str[i] == 'g')
         {
            multiplier = 1024 * 1024 * 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'K' || str[i] == 'k')
         {
            multiplier = 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'B' || str[i] == 'b')
         {
            multiplier = 1;
            multiplier_set = true;
         }
      }
      else
      {
         // do not allow alien chars
         goto error;
      }
   }

   value[index] = '\0';
   if (!as_long(value, &l_value))
   {
      // sanity check: the value
      // must be a positive number!
      if (l_value >= 0)
      {
         *bytes = l_value * multiplier;
      }
      else
      {
         goto error;
      }

      return 0;
   }
   else
   {
error:
      *bytes = default_bytes;
      return 1;
   }
}

static int
as_endpoints(char* str, struct configuration* config, bool reload)
{
   int idx = 0;
   char* token = NULL;
   char host[MISC_LENGTH] = {0};
   char port[6] = {0};

   token = strtok((char*) str, ",");

   while (token != NULL && idx < NUMBER_OF_ENDPOINTS)
   {
      char* t = token;
      char* n = NULL;

      n = pgexporter_remove_whitespace(t);
      t = n;

      n = pgexporter_remove_prefix(t, "https://");
      free(t);
      t = n;

      n = pgexporter_remove_prefix(t, "http://");
      free(t);
      t = n;

      n = pgexporter_remove_suffix(t, "/metrics");
      free(t);
      t = n;

      n = pgexporter_remove_suffix(t, "/");
      free(t);
      t = n;

      /*
       * Each endpoint is host:port.
       * Host is of length [0, 127].
       * Port is of length [0, 5] (16-bit unsigned integer).
       */
      if (sscanf(t, "%127[^:]:%5s", host, port) == 2)
      {
         bool found = false;

         if (!reload)
         {
            for (int i = 0; i <= idx; i++)
            {
               if (!strcmp(config->endpoints[i].host, host) && config->endpoints[i].port == atoi(port))
               {
                  found = true;
               }
            }
         }

         if (!found)
         {
            snprintf(config->endpoints[idx].host, MISC_LENGTH, "%s", host);
            config->endpoints[idx].port = atoi(port);

            pgexporter_log_trace("Bridge Endpoint %d | Host: %s, Port: %s", idx, host, port);

            idx++;
         }
         else
         {
            pgexporter_log_warn("Duplicated endpoint: %s:%s", host, port);
         }

         memset(host, 0, sizeof(host));
         memset(port, 0, sizeof(port));
      }
      else
      {
         pgexporter_log_error("Error parsing endpoint: %s", token);
         goto error;
      }

      free(t);

      token = strtok(NULL, ",");
   }

   config->number_of_endpoints = idx;

   return 0;

error:

   memset(config->endpoints, 0, sizeof(config->endpoints));
   config->number_of_endpoints = 0;

   return 1;
}

static bool
transfer_configuration(struct configuration* config, struct configuration* reload)
{
   char* old_endpoints = NULL;
   char* new_endpoints = NULL;
   bool changed = false;

#ifdef HAVE_SYSTEMD
   sd_notify(0, "RELOADING=1");
#endif

   memcpy(config->host, reload->host, MISC_LENGTH);
   config->metrics = reload->metrics;
   config->metrics_cache_max_age = reload->metrics_cache_max_age;
   if (restart_int("metrics_cache_max_size", config->metrics_cache_max_size, reload->metrics_cache_max_size))
   {
      changed = true;
   }
   if (restart_int("bridge", config->bridge, reload->bridge))
   {
      changed = true;
   }

   if (config->number_of_endpoints > 0)
   {
      for (int i = 0; i < config->number_of_endpoints; i++)
      {
         old_endpoints = pgexporter_append(old_endpoints, config->endpoints[i].host);
         old_endpoints = pgexporter_append_char(old_endpoints, ':');
         old_endpoints = pgexporter_append_int(old_endpoints, config->endpoints[i].port);

         if (i < config->number_of_endpoints - 1)
         {
            old_endpoints = pgexporter_append_char(old_endpoints, ',');
         }
      }
   }
   else
   {
      old_endpoints = pgexporter_append(old_endpoints, "");
   }

   if (reload->number_of_endpoints > 0)
   {
      for (int i = 0; i < reload->number_of_endpoints; i++)
      {
         new_endpoints = pgexporter_append(new_endpoints, reload->endpoints[i].host);
         new_endpoints = pgexporter_append_char(new_endpoints, ':');
         new_endpoints = pgexporter_append_int(new_endpoints, reload->endpoints[i].port);

         if (i < reload->number_of_endpoints - 1)
         {
            new_endpoints = pgexporter_append_char(new_endpoints, ',');
         }
      }
   }
   else
   {
      new_endpoints = pgexporter_append(new_endpoints, "");
   }

   if (restart_string("bridge_endpoints", old_endpoints, new_endpoints))
   {
      changed = true;
   }

   config->bridge_cache_max_age = reload->bridge_cache_max_age;
   if (restart_int("bridge_cache_max_size", config->bridge_cache_max_size, reload->bridge_cache_max_size))
   {
      changed = true;
   }
   if (restart_int("bridge_json", config->bridge_json, reload->bridge_json))
   {
      changed = true;
   }
   if (restart_int("bridge_json_cache_max_size", config->bridge_json_cache_max_size, reload->bridge_json_cache_max_size))
   {
      changed = true;
   }
   config->management = reload->management;
   config->cache = reload->cache;

   /* log_type */
   if (restart_int("log_type", config->log_type, reload->log_type))
   {
      changed = true;
   }
   config->log_level = reload->log_level;
   // if the log main parameters have changed, we need
   // to restart the logging system
   if (strncmp(config->log_path, reload->log_path, MISC_LENGTH)
       || config->log_rotation_size != reload->log_rotation_size
       || config->log_rotation_age != reload->log_rotation_age
       || config->log_mode != reload->log_mode)
   {
      pgexporter_log_debug("Log restart triggered!");
      pgexporter_stop_logging();
      config->log_rotation_size = reload->log_rotation_size;
      config->log_rotation_age = reload->log_rotation_age;
      config->log_mode = reload->log_mode;
      memcpy(config->log_line_prefix, reload->log_line_prefix, MISC_LENGTH);
      memcpy(config->log_path, reload->log_path, MISC_LENGTH);
      pgexporter_start_logging();
   }
   /* log_lock */

   config->tls = reload->tls;
   memcpy(config->tls_cert_file, reload->tls_cert_file, MAX_PATH);
   memcpy(config->tls_key_file, reload->tls_key_file, MAX_PATH);
   memcpy(config->tls_ca_file, reload->tls_ca_file, MAX_PATH);
   memcpy(config->metrics_cert_file, reload->metrics_cert_file, MAX_PATH);
   memcpy(config->metrics_key_file, reload->metrics_key_file, MAX_PATH);
   memcpy(config->metrics_ca_file, reload->metrics_ca_file, MAX_PATH);

   config->blocking_timeout = reload->blocking_timeout;
   config->authentication_timeout = reload->authentication_timeout;
   /* pidfile */
   if (restart_string("pidfile", config->pidfile, reload->pidfile))
   {
      changed = true;
   }

   /* libev */
   if(restart_string("libev", config->libev, reload->libev)){
      changed = true;
   };
   config->keep_alive = reload->keep_alive;
   config->nodelay = reload->nodelay;
   config->non_blocking = reload->non_blocking;
   config->backlog = reload->backlog;
   /* hugepage */
   if (restart_int("hugepage", config->hugepage, reload->hugepage))
   {
      changed = true;
   }

   /* update_process_title */
   if (restart_int("update_process_title", config->update_process_title, reload->update_process_title))
   {
      changed = true;
   }

   /* unix_socket_dir */
   if (restart_string("unix_socket_dir", config->unix_socket_dir, reload->unix_socket_dir))
   {
      changed = true;
   }

   memset(&config->servers[0], 0, sizeof(struct server) * NUMBER_OF_SERVERS);
   for (int i = 0; i < reload->number_of_servers; i++)
   {
      copy_server(&config->servers[i], &reload->servers[i]);
   }
   config->number_of_servers = reload->number_of_servers;

   memset(&config->users[0], 0, sizeof(struct user) * NUMBER_OF_USERS);
   for (int i = 0; i < reload->number_of_users; i++)
   {
      copy_user(&config->users[i], &reload->users[i]);
   }
   config->number_of_users = reload->number_of_users;

   memset(&config->admins[0], 0, sizeof(struct user) * NUMBER_OF_ADMINS);
   for (int i = 0; i < reload->number_of_admins; i++)
   {
      copy_user(&config->admins[i], &reload->admins[i]);
   }
   config->number_of_admins = reload->number_of_admins;

   /* prometheus */
   memcpy(config->metrics_path, reload->metrics_path, MAX_PATH);
   for (int i = 0; i < reload->number_of_metrics; i++)
   {
      copy_promethus(&config->prometheus[i], &reload->prometheus[i]);
   }
   config->number_of_metrics = reload->number_of_metrics;

   /* endpoint */
   for (int i = 0; i < reload->number_of_endpoints; i++)
   {
      copy_endpoint(&config->endpoints[i], &reload->endpoints[i]);
   }
   config->number_of_endpoints = reload->number_of_endpoints;

#ifdef HAVE_SYSTEMD
   sd_notify(0, "READY=1");
#endif

   free(old_endpoints);
   free(new_endpoints);

   return changed;
}

static void
copy_server(struct server* dst, struct server* src)
{
   memcpy(&dst->name[0], &src->name[0], MISC_LENGTH);
   memcpy(&dst->host[0], &src->host[0], MISC_LENGTH);
   dst->port = src->port;
   memcpy(&dst->username[0], &src->username[0], MAX_USERNAME_LENGTH);
   memcpy(&dst->data[0], &src->data[0], MISC_LENGTH);
   memcpy(&dst->wal[0], &src->wal[0], MISC_LENGTH);
   memcpy(&dst->extensions_config[0], &src->extensions_config[0], MAX_EXTENSIONS_CONFIG_LENGTH);
   dst->fd = src->fd;
}

static void
copy_user(struct user* dst, struct user* src)
{
   memcpy(&dst->username[0], &src->username[0], MAX_USERNAME_LENGTH);
   memcpy(&dst->password[0], &src->password[0], MAX_PASSWORD_LENGTH);
}

static void
copy_promethus(struct prometheus* dst, struct prometheus* src)
{
   memcpy(dst->tag, src->tag, MISC_LENGTH);
   memcpy(dst->collector, src->collector, MAX_COLLECTOR_LENGTH);
   dst->sort_type = src->sort_type;
   dst->server_query_type = src->server_query_type;

   // Initialize pointers to NULL before copying
   dst->pg_root = NULL;
   dst->ext_root = NULL;
   
   // Only copy if source pointers are valid and not NULL
   if (src != NULL && src->pg_root != NULL)
   {
      pgexporter_copy_pg_query_alts(&dst->pg_root, src->pg_root);
   }
   
   if (src != NULL && src->ext_root != NULL)
   {
      pgexporter_copy_extension_query_alts(src->ext_root, &dst->ext_root);
   }
}



static void
copy_endpoint(struct endpoint* dst, struct endpoint* src)
{
   memcpy(dst->host, src->host, MISC_LENGTH);
   dst->port = src->port;
}

static int
restart_int(char* name, int e, int n)
{
   if (e != n)
   {
      pgexporter_log_info("Restart required for %s - Existing %d New %d", name, e, n);
      return 1;
   }

   return 0;
}

static int
restart_string(char* name, char* e, char* n)
{
   if (strcmp(e, n))
   {
      pgexporter_log_info("Restart required for %s - Existing %s New %s", name, e, n);
      return 1;
   }

   return 0;
}

static bool
is_empty_string(char* s)
{
   if (s == NULL)
   {
      return true;
   }

   if (!strcmp(s, ""))
   {
      return true;
   }

   for (size_t i = 0; i < strlen(s); i++)
   {
      if (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
      {
         /* Ok */
      }
      else
      {
         return false;
      }
   }

   return true;
}

static bool
is_valid_config_key(const char* config_key, struct config_key_info* key_info)
{
   struct configuration* config;
   int dot_count = 0;
   int begin = 0, end = -1;

   if (!config_key || strlen(config_key) == 0 || !key_info)
   {
      return false;
   }

   config = (struct configuration*)shmem;

   // Initialize output structure
   memset(key_info, 0, sizeof(struct config_key_info));

   // Basic format validation
   size_t len = strlen(config_key);
   if (config_key[0] == '.' || config_key[len - 1] == '.')
   {
      pgexporter_log_debug("Invalid config key: starts or ends with dot: %s", config_key);
      return false;
   }

   // Check for consecutive dots and count total dots
   for (size_t i = 0; i < len - 1; i++)
   {
      if (config_key[i] == '.')
      {
         dot_count++;
         if (config_key[i + 1] == '.')
         {
            pgexporter_log_debug("Invalid config key: consecutive dots: %s", config_key);
            return false;
         }
      }
   }
   if (config_key[len - 1] == '.')
   {
      dot_count++;
   }

   if (dot_count > 2)
   {
      pgexporter_log_debug("Invalid config key: too many dots (%d): %s", dot_count, config_key);
      return false;
   }

   // Parse the key into components
   for (size_t i = 0; i < len; i++)
   {
      if (config_key[i] == '.')
      {
         if (!strlen(key_info->section))
         {
            // First dot: extract section
            memcpy(key_info->section, &config_key[begin], i - begin);
            key_info->section[i - begin] = '\0';
            begin = i + 1;
         }
         else if (!strlen(key_info->context))
         {
            // Second dot: extract context
            memcpy(key_info->context, &config_key[begin], i - begin);
            key_info->context[i - begin] = '\0';
            begin = i + 1;
         }
      }
      end = i;
   }

   // Extract the final part (key) and determine configuration type
   if (dot_count == 0)
   {
      // Case: "workers" (direct key access - treated as main config)
      memcpy(key_info->key, config_key, strlen(config_key));
      key_info->key[strlen(config_key)] = '\0';
      strcpy(key_info->section, PGEXPORTER_MAIN_INI_SECTION);
      key_info->is_main_section = true;
      key_info->section_type = 0;
   }
   else if (dot_count == 1)
   {
      // Case: "pgexporter.workers" (main section)
      memcpy(key_info->key, &config_key[begin], end - begin + 1);
      key_info->key[end - begin + 1] = '\0';
      if (!strncmp(key_info->section, PGEXPORTER_MAIN_INI_SECTION, MISC_LENGTH))
      {
         key_info->is_main_section = true;
         key_info->section_type = 0;
      }
      else
      {
         pgexporter_log_debug("Invalid section for single dot notation: %s (expected 'pgexporter')", key_info->section);
         return false;
      }
   }
   else if (dot_count == 2)
   {
      // Case: "server.primary.host" (server section)
      memcpy(key_info->key, &config_key[begin], end - begin + 1);
      key_info->key[end - begin + 1] = '\0';
      key_info->is_main_section = false;
      if (!strncmp(key_info->section, "server", MISC_LENGTH))
      {
         key_info->section_type = 1;
      }
      else
      {
         pgexporter_log_debug("Unknown section type: %s (expected 'server')", key_info->section);
         return false;
      }
   }

   // Validate that entries exist in current configuration
   switch (key_info->section_type)
   {
      case 0: // Main section
         // All main keys are valid if they exist in the parsing logic
         break;
      case 1: // Server section
      {
         bool server_found = false;
         for (int i = 0; i < config->number_of_servers; i++)
         {
            if (!strncmp(config->servers[i].name, key_info->context, MISC_LENGTH))
            {
               server_found = true;
               break;
            }
         }
         if (!server_found)
         {
            pgexporter_log_debug("Server '%s' not found in configuration", key_info->context);
            return false;
         }
      }
      break;
      default:
         pgexporter_log_debug("Unknown section type: %d", key_info->section_type);
         return false;
   }

   return true;
}

// static int
// apply_configuration(char* config_key, char* config_value,
//                     struct config_key_info* key_info,
//                     bool* restart_required)
// {
//    struct configuration* current_config;
//    struct configuration* temp_config;
//    size_t config_size = 0;

//    // Initialize restart flag
//    *restart_required = false;

//    // Get the currently running configuration
//    current_config = (struct configuration*)shmem;

//    // Create temporary configuration
//    config_size = sizeof(struct configuration);
//    if (pgexporter_create_shared_memory(config_size, HUGEPAGE_OFF, (void**)&temp_config))
//    {
//       goto error;
//    }

//    // // Initialize temp config properly
//    // pgexporter_init_configuration((void*)temp_config);
   
//    // Copy current config to temp, but handle complex structures properly
//    memcpy(temp_config, current_config, config_size);
   
//    // // Reset Prometheus query alternatives pointers to avoid invalid references
//    // for (int i = 0; i < temp_config->number_of_metrics; i++)
//    // {
//    //    temp_config->prometheus[i].pg_root = NULL;
//    //    temp_config->prometheus[i].ext_root = NULL;
//    // }
   
//    // // Copy Prometheus structures properly
//    // for (int i = 0; i < current_config->number_of_metrics; i++)
//    // {
//    //    if (current_config->prometheus[i].pg_root != NULL)
//    //    {
//    //       pgexporter_copy_pg_query_alts(&temp_config->prometheus[i].pg_root, current_config->prometheus[i].pg_root);
//    //    }
//    //    if (current_config->prometheus[i].ext_root != NULL)
//    //    {
//    //       pgexporter_copy_extension_query_alts(current_config->prometheus[i].ext_root, &temp_config->prometheus[i].ext_root);
//    //    }
//    // }

//    // Apply configuration changes using the provided key_info
//    pgexporter_log_debug("Applying configuration: section='%s', context='%s', key='%s', section_type=%d",
//                         key_info->section, key_info->context, key_info->key, key_info->section_type);

//    switch (key_info->section_type)
//    {
//       case 0: // Main configuration
//          if (apply_main_configuration(temp_config, NULL, PGEXPORTER_MAIN_INI_SECTION, key_info->key, config_value))
//          {
//             goto error;
//          }
//          break;
//       case 1: // Server configuration
//       {
//          for (int i = 0; i < temp_config->number_of_servers; i++)
//          {
//             if (!strncmp(temp_config->servers[i].name, key_info->context, MISC_LENGTH))
//             {
//                if (apply_main_configuration(temp_config, &temp_config->servers[i], key_info->context, key_info->key, config_value))
//                {
//                   goto error;
//                }
//                break;
//             }
//          }
//       }
//       break;
//       default:
//          pgexporter_log_error("Unknown section type: %d", key_info->section_type);
//          goto error;
//    }

//    // Validate the temporary configuration
//    if (pgexporter_validate_configuration(temp_config))
//    {
//       pgexporter_log_error("Configuration validation failed for %s = %s", config_key, config_value);
//       goto error;
//    }

//    // Check if restart is required by comparing configurations
// *restart_required = transfer_configuration(current_config, temp_config);

// if (*restart_required)
// {
//     pgexporter_log_info("Configuration change %s = %s requires restart, not applied", config_key, config_value);
//     // Do NOT apply changes
// }
// else
// {
//     pgexporter_log_info("Configuration change %s = %s applied successfully", config_key, config_value);
//     // No need to call transfer_configuration again
// }


//    // Clean up Prometheus structures before destroying temp_config
//    for (int i = 0; i < temp_config->number_of_metrics; i++)
//    {
//       if (temp_config->prometheus[i].pg_root != NULL)
//       {
//          pgexporter_free_pg_node_avl(&temp_config->prometheus[i].pg_root);
//       }
//       if (temp_config->prometheus[i].ext_root != NULL)
//       {
//          pgexporter_free_extension_node_avl(&temp_config->prometheus[i].ext_root);
//       }
//    }
   
//    // Clean up
//    if (pgexporter_destroy_shared_memory((void*)temp_config, config_size))
//    {
//       goto error;
//    }

//    return 0;

// error:
//    if (temp_config != NULL)
//    {
//       // Clean up Prometheus structures before destroying temp_config
//       for (int i = 0; i < temp_config->number_of_metrics; i++)
//       {
//          if (temp_config->prometheus[i].pg_root != NULL)
//          {
//             pgexporter_free_pg_node_avl(&temp_config->prometheus[i].pg_root);
//          }
//          if (temp_config->prometheus[i].ext_root != NULL)
//          {
//             pgexporter_free_extension_node_avl(&temp_config->prometheus[i].ext_root);
//          }
//       }
//       pgexporter_destroy_shared_memory((void*)temp_config, config_size);
//    }
//    return 1;
// }

// int apply_configuration(char* config_key, char* config_value, struct config_key_info* key_info, bool* restart_required)
// {
//     struct configuration* current_config;
//     struct configuration* temp_config = NULL;
//     size_t config_size;

//     current_config = (struct configuration*)shmem;
//     config_size = sizeof(struct configuration);

//     *restart_required = false;

//     // Allocate and initialize temp config
//     if (pgexporter_create_shared_memory(config_size, HUGEPAGE_OFF, (void**)&temp_config))
//         goto error;

//     pgexporter_init_configuration((void*)temp_config);

//    //  // Read all config files
//    //  if (pgexporter_read_configuration((void*)temp_config, current_config->configuration_path))
//    //      goto error;
//    //  if (pgexporter_read_users_configuration((void*)temp_config, current_config->users_path))
//    //      goto error;
//    //  if (strcmp("", current_config->admins_path))
//    //      if (pgexporter_read_admins_configuration((void*)temp_config, current_config->admins_path))
//    //          goto error;

//     // Load metrics
//    //  if (pgexporter_read_internal_yaml_metrics(temp_config, true))
//    //      goto error;
//    //  if (strlen(temp_config->metrics_path) > 0)
//    //      if (pgexporter_read_metrics_configuration((void*)temp_config))
//    //          goto error;

//     // Apply the config change
//     switch (key_info->section_type)
//     {
//         case 0:
//             if (apply_main_configuration(temp_config, NULL, PGEXPORTER_MAIN_INI_SECTION, key_info->key, config_value))
//                 goto error;
//             break;
//         case 1:
//             for (int i = 0; i < temp_config->number_of_servers; i++)
//                 if (!strncmp(temp_config->servers[i].name, key_info->context, MISC_LENGTH))
//                     if (apply_main_configuration(temp_config, &temp_config->servers[i], key_info->context, key_info->key, config_value))
//                         goto error;
//             break;
//         default:
//             goto error;
//     }

//     // Validate temp config
//     if (pgexporter_validate_configuration(temp_config))
//         goto error;
//     if (pgexporter_validate_users_configuration(temp_config))
//         goto error;
//     if (pgexporter_validate_admins_configuration(temp_config))
//         goto error;

//     // Transfer configuration
//     *restart_required = transfer_configuration(current_config, temp_config);

//     // Free Prometheus structures
//     for (int i = 0; temp_config != NULL && i < temp_config->number_of_metrics; i++)
//     {
//         pgexporter_free_pg_query_alts(temp_config);
//     }
//     pgexporter_free_extension_query_alts(temp_config);

//     pgexporter_destroy_shared_memory((void*)temp_config, config_size);

//     return 0;

// error:
//     if (temp_config != NULL)
//     {
//         for (int i = 0; i < temp_config->number_of_metrics; i++){
//             pgexporter_free_pg_query_alts(temp_config);
//         }
//         pgexporter_free_extension_query_alts(temp_config);
//         pgexporter_destroy_shared_memory((void*)temp_config, config_size);
//     }
//     return 1;
// }

// static int
// apply_configuration(char* config_key, char* config_value,
//                     struct config_key_info* key_info,
//                     bool* restart_required)
// {
//    struct configuration* current_config;
//    struct configuration* temp_config;
//    size_t config_size = 0;

//    // Initialize restart flag
//    *restart_required = false;

//    // Get the currently running configuration
//    current_config = (struct configuration*)shmem;

//    // Create temporary configuration following the same pattern as pgexporter_reload_configuration
//    config_size = sizeof(struct configuration);
//    if (pgexporter_create_shared_memory(config_size, HUGEPAGE_OFF, (void**)&temp_config))
//    {
//       goto error;
//    }

//    // Initialize temp config properly - this is crucial!
//    pgexporter_init_configuration((void*)temp_config);
   
//    // Read the current configuration files to properly initialize temp_config
//    // This ensures all structures are properly initialized like in reload_configuration
//    if (pgexporter_read_configuration((void*)temp_config, current_config->configuration_path))
//    {
//       pgexporter_log_error("Failed to read configuration file during apply");
//       goto error;
//    }

//    if (pgexporter_read_users_configuration((void*)temp_config, current_config->users_path))
//    {
//       pgexporter_log_error("Failed to read users configuration during apply");
//       goto error;
//    }

//    if (strcmp("", current_config->admins_path))
//    {
//       if (pgexporter_read_admins_configuration((void*)temp_config, current_config->admins_path))
//       {
//          pgexporter_log_error("Failed to read admins configuration during apply");
//          goto error;
//       }
//    }

//    // Read internal YAML metrics to properly initialize Prometheus structures
//    if (pgexporter_read_internal_yaml_metrics(temp_config, true))
//    {
//       pgexporter_log_error("Failed to read internal YAML metrics during apply");
//       goto error;
//    }

//    // Read metrics configuration if path is set
//    if (strlen(temp_config->metrics_path) > 0)
//    {
//       if (pgexporter_read_metrics_configuration((void*)temp_config))
//       {
//          pgexporter_log_error("Failed to read metrics configuration during apply");
//          goto error;
//       }
//    }

//    // Apply configuration changes using the provided key_info
//    pgexporter_log_debug("Applying configuration: section='%s', context='%s', key='%s', section_type=%d",
//                         key_info->section, key_info->context, key_info->key, key_info->section_type);

//    switch (key_info->section_type)
//    {
//       case 0: // Main configuration
//          if (apply_main_configuration(temp_config, NULL, PGEXPORTER_MAIN_INI_SECTION, key_info->key, config_value))
//          {
//             goto error;
//          }
//          break;
//       case 1: // Server configuration
//       {
//          for (int i = 0; i < temp_config->number_of_servers; i++)
//          {
//             if (!strncmp(temp_config->servers[i].name, key_info->context, MISC_LENGTH))
//             {
//                if (apply_main_configuration(temp_config, &temp_config->servers[i], key_info->context, key_info->key, config_value))
//                {
//                   goto error;
//                }
//                break;
//             }
//          }
//       }
//       break;
//       default:
//          pgexporter_log_error("Unknown section type: %d", key_info->section_type);
//          goto error;
//    }

//    // Validate the temporary configuration - following reload_configuration pattern
//    if (pgexporter_validate_configuration(temp_config))
//    {
//       pgexporter_log_error("Configuration validation failed for %s = %s", config_key, config_value);
//       goto error;
//    }

//    if (pgexporter_validate_users_configuration(temp_config))
//    {
//       pgexporter_log_error("Users configuration validation failed for %s = %s", config_key, config_value);
//       goto error;
//    }

//    if (pgexporter_validate_admins_configuration(temp_config))
//    {
//       pgexporter_log_error("Admins configuration validation failed for %s = %s", config_key, config_value);
//       goto error;
//    }

//    // Check if restart is required by comparing configurations
//    *restart_required = transfer_configuration(current_config, temp_config);

//    if (*restart_required)
//    {
//       pgexporter_log_info("Configuration change %s = %s requires restart, not applied", config_key, config_value);
//       // Do NOT apply changes
//    }
//    else
//    {
//       pgexporter_log_info("Configuration change %s = %s applied successfully", config_key, config_value);
//       // No need to call transfer_configuration again - it already applied the changes
//    }

//    // Clean up following the same pattern as reload_configuration
//    for (int i = 0; temp_config != NULL && i < temp_config->number_of_metrics; i++)
//    {
//       pgexporter_free_pg_query_alts(temp_config);
//    }
//    pgexporter_free_extension_query_alts(temp_config);
//    pgexporter_destroy_shared_memory((void*)temp_config, config_size);

//    return 0;

// error:
//    if (temp_config != NULL)
//    {
//       // Clean up following the same pattern as reload_configuration
//       for (int i = 0; temp_config != NULL && i < temp_config->number_of_metrics; i++)
//       {
//          pgexporter_free_pg_query_alts(temp_config);
//       }
//       pgexporter_free_extension_query_alts(temp_config);
//       pgexporter_destroy_shared_memory((void*)temp_config, config_size);
//    }
//    return 1;
// }

static int
apply_configuration(char* config_key, char* config_value,
                    struct config_key_info* key_info,
                    bool* restart_required)
{
   struct configuration* current_config;
   struct configuration* temp_config;
   size_t config_size = 0;

   // Initialize restart flag
   *restart_required = false;

   // Get the currently running configuration
   current_config = (struct configuration*)shmem;

   // Create temporary configuration
   config_size = sizeof(struct configuration);
   if (pgexporter_create_shared_memory(config_size, HUGEPAGE_OFF, (void**)&temp_config))
   {
      goto error;
   }

   // // Initialize temp config properly
   // pgexporter_init_configuration((void*)temp_config);
   
   // Copy current config to temp, but handle complex structures properly
   memcpy(temp_config, current_config, config_size);

   for (int i = 0; i < temp_config->number_of_metrics; i++)
   {
      // Free the duplicated pointers in temp_config
      if (temp_config->prometheus[i].pg_root != NULL)
      {
         pgexporter_free_pg_node_avl(&temp_config->prometheus[i].pg_root);
         // pgexporter_free_pg_node_avl should set it to NULL, but let's be explicit
         temp_config->prometheus[i].pg_root = NULL;
      }
      
      if (temp_config->prometheus[i].ext_root != NULL)
      {
         pgexporter_free_extension_node_avl(&temp_config->prometheus[i].ext_root);
         // pgexporter_free_extension_node_avl should set it to NULL, but let's be explicit
         temp_config->prometheus[i].ext_root = NULL;
      }
   }
   
   // // Reset Prometheus query alternatives pointers to avoid invalid references
   // for (int i = 0; i < temp_config->number_of_metrics; i++)
   // {
   //    temp_config->prometheus[i].pg_root = NULL;
   //    temp_config->prometheus[i].ext_root = NULL;
   // }
   
   // // Copy Prometheus structures properly
   // for (int i = 0; i < current_config->number_of_metrics; i++)
   // {
   //    if (current_config->prometheus[i].pg_root != NULL)
   //    {
   //       pgexporter_copy_pg_query_alts(&temp_config->prometheus[i].pg_root, current_config->prometheus[i].pg_root);
   //    }
   //    if (current_config->prometheus[i].ext_root != NULL)
   //    {
   //       pgexporter_copy_extension_query_alts(current_config->prometheus[i].ext_root, &temp_config->prometheus[i].ext_root);
   //    }
   // }

   // Apply configuration changes using the provided key_info
   pgexporter_log_debug("Applying configuration: section='%s', context='%s', key='%s', section_type=%d",
                        key_info->section, key_info->context, key_info->key, key_info->section_type);

   switch (key_info->section_type)
   {
      case 0: // Main configuration
         if (apply_main_configuration(temp_config, NULL, PGEXPORTER_MAIN_INI_SECTION, key_info->key, config_value))
         {
            goto error;
         }
         break;
      case 1: // Server configuration
      {
         for (int i = 0; i < temp_config->number_of_servers; i++)
         {
            if (!strncmp(temp_config->servers[i].name, key_info->context, MISC_LENGTH))
            {
               if (apply_main_configuration(temp_config, &temp_config->servers[i], key_info->context, key_info->key, config_value))
               {
                  goto error;
               }
               break;
            }
         }
      }
      break;
      default:
         pgexporter_log_error("Unknown section type: %d", key_info->section_type);
         goto error;
   }

   // Validate the temporary configuration
   if (pgexporter_validate_configuration(temp_config))
   {
      pgexporter_log_error("Configuration validation failed for %s = %s", config_key, config_value);
      goto error;
   }

   // Check if restart is required by comparing configurations
   *restart_required = transfer_configuration(current_config, temp_config);

   if (*restart_required)
   {
      pgexporter_log_info("Configuration change %s = %s requires restart, not applied", config_key, config_value);
      // Do NOT apply changes
   }
   else
   {
      pgexporter_log_info("Configuration change %s = %s applied successfully", config_key, config_value);
      // No need to call transfer_configuration again - it already applied the changes
   }

   // Clean up Prometheus structures before destroying temp_config
   // for (int i = 0; i < temp_config->number_of_metrics; i++)
   // {
   //    if (temp_config->prometheus[i].pg_root != NULL)
   //    {
   //       pgexporter_free_pg_node_avl(&temp_config->prometheus[i].pg_root);
   //    }
   //    if (temp_config->prometheus[i].ext_root != NULL)
   //    {
   //       pgexporter_free_extension_node_avl(&temp_config->prometheus[i].ext_root);
   //    }
   // }
   
   // // Clean up
   // pgexporter_destroy_shared_memory((void*)temp_config, config_size);

   // for (int i = 0; temp_config != NULL && i < temp_config->number_of_metrics; i++)
   // {
   //    pgexporter_free_pg_query_alts(temp_config);
   // }
   // pgexporter_free_extension_query_alts(temp_config);

   pgexporter_destroy_shared_memory((void*)temp_config, config_size);

   // pgexporter_log_debug("Reload: Success");

   return 0;

error:
   if (temp_config != NULL)
   {
      // Clean up Prometheus structures before destroying temp_config
      // for (int i = 0; i < temp_config->number_of_metrics; i++)
      // {
      //    if (temp_config->prometheus[i].pg_root != NULL)
      //    {
      //       pgexporter_free_pg_node_avl(&temp_config->prometheus[i].pg_root);
      //    }
      //    if (temp_config->prometheus[i].ext_root != NULL)
      //    {
      //       pgexporter_free_extension_node_avl(&temp_config->prometheus[i].ext_root);
      //    }
      // }
      // pgexporter_destroy_shared_memory((void*)temp_config, config_size);
   // for (int i = 0; temp_config != NULL && i < temp_config->number_of_metrics; i++)
   // {
   //    pgexporter_free_pg_query_alts(temp_config);
   // }
   // pgexporter_free_extension_query_alts(temp_config);

   pgexporter_destroy_shared_memory((void*)temp_config, config_size);
   }
   return 1;
}

static int
apply_main_configuration(struct configuration* config, struct server* srv, char* section __attribute__((unused)), char* key, char* value)
{
   size_t max;
   bool unknown = false;

   // Server-specific configuration
   if (srv != NULL)
   {
      if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_HOST))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(srv->host, value, max);
         srv->host[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_PORT))
      {
         if (as_int(value, &srv->port))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_USER))
      {
         max = strlen(value);
         if (max > MAX_USERNAME_LENGTH - 1)
         {
            max = MAX_USERNAME_LENGTH - 1;
         }
         memcpy(srv->username, value, max);
         srv->username[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_DATA_DIR))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(srv->data, value, max);
         srv->data[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_WAL_DIR))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(srv->wal, value, max);
         srv->wal[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_TLS_CERT_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(srv->tls_cert_file, value, max);
         srv->tls_cert_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_TLS_KEY_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(srv->tls_key_file, value, max);
         srv->tls_key_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_SERVER_ARGUMENT_TLS_CA_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(srv->tls_ca_file, value, max);
         srv->tls_ca_file[max] = '\0';
      }
      else
      {
         unknown = true;
      }
   }
   else
   {
      // Main configuration
      if (!strcmp(key, CONFIGURATION_ARGUMENT_HOST))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(config->host, value, max);
         config->host[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS))
      {
         if (as_int(value, &config->metrics))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_AGE))
      {
         if (as_seconds(value, &config->metrics_cache_max_age, 0))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_SIZE))
      {
         long l = 0;
         if (as_bytes(value, &l, 0))
         {
            unknown = true;
         }
         config->metrics_cache_max_size = (size_t)l;
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_MANAGEMENT))
      {
         if (as_int(value, &config->management))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE))
      {
         if (as_int(value, &config->bridge))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_AGE))
      {
         if (as_seconds(value, &config->bridge_cache_max_age, 0))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_SIZE))
      {
         long l = 0;
         if (as_bytes(value, &l, 0))
         {
            unknown = true;
         }
         config->bridge_cache_max_size = (size_t)l;
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE_JSON))
      {
         if (as_int(value, &config->bridge_json))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE_JSON_CACHE_MAX_SIZE))
      {
         long l = 0;
         if (as_bytes(value, &l, 0))
         {
            unknown = true;
         }
         config->bridge_json_cache_max_size = (size_t)l;
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BRIDGE_ENDPOINTS))
      {
         if (as_endpoints(value, config, true))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_CACHE))
      {
         if (as_bool(value, &config->cache))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_LEVEL))
      {
         config->log_level = as_logging_level(value);
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_TYPE))
      {
         config->log_type = as_logging_type(value);
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_PATH))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(config->log_path, value, max);
         config->log_path[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_MODE))
      {
         config->log_mode = as_logging_mode(value);
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_ROTATION_SIZE))
      {
         if (as_logging_rotation_size(value, &config->log_rotation_size))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_ROTATION_AGE))
      {
         if (as_logging_rotation_age(value, &config->log_rotation_age))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LOG_LINE_PREFIX))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(config->log_line_prefix, value, max);
         config->log_line_prefix[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_TLS))
      {
         if (as_bool(value, &config->tls))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_TLS_CERT_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->tls_cert_file, value, max);
         config->tls_cert_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_TLS_KEY_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->tls_key_file, value, max);
         config->tls_key_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_TLS_CA_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->tls_ca_file, value, max);
         config->tls_ca_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_CERT_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->metrics_cert_file, value, max);
         config->metrics_cert_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_KEY_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->metrics_key_file, value, max);
         config->metrics_key_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_CA_FILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->metrics_ca_file, value, max);
         config->metrics_ca_file[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BLOCKING_TIMEOUT))
      {
         if (as_int(value, &config->blocking_timeout))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_AUTHENTICATION_TIMEOUT))
      {
         if (as_int(value, &config->authentication_timeout))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_PIDFILE))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->pidfile, value, max);
         config->pidfile[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_UPDATE_PROCESS_TITLE))
      {
         config->update_process_title = as_update_process_title(value, UPDATE_PROCESS_TITLE_VERBOSE);
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_LIBEV))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(config->libev, value, max);
         config->libev[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_KEEP_ALIVE))
      {
         if (as_bool(value, &config->keep_alive))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_NODELAY))
      {
         if (as_bool(value, &config->nodelay))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_NON_BLOCKING))
      {
         if (as_bool(value, &config->non_blocking))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_BACKLOG))
      {
         if (as_int(value, &config->backlog))
         {
            unknown = true;
         }
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_HUGEPAGE))
      {
         config->hugepage = as_hugepage(value);
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_UNIX_SOCKET_DIR))
      {
         max = strlen(value);
         if (max > MISC_LENGTH - 1)
         {
            max = MISC_LENGTH - 1;
         }
         memcpy(config->unix_socket_dir, value, max);
         config->unix_socket_dir[max] = '\0';
      }
      else if (!strcmp(key, CONFIGURATION_ARGUMENT_METRICS_PATH))
      {
         max = strlen(value);
         if (max > MAX_PATH - 1)
         {
            max = MAX_PATH - 1;
         }
         memcpy(config->metrics_path, value, max);
         config->metrics_path[max] = '\0';
      }
      else
      {
         unknown = true;
      }
   }

   if (unknown)
   {
      pgexporter_log_error("Unknown configuration key: %s", key);
      return 1;
   }

   return 0;
}

static int
write_config_value(char* buffer, char* config_key, size_t buffer_size)
{
   struct configuration* config;
   struct config_key_info key_info;

   if (!buffer || !config_key || buffer_size == 0)
   {
      return 1;
   }

   config = (struct configuration*)shmem;

   if (!is_valid_config_key(config_key, &key_info))
   {
      return 1;
   }

   memset(buffer, 0, buffer_size);

   switch (key_info.section_type)
   {
      case 0: // Main configuration
         if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_HOST))
         {
            snprintf(buffer, buffer_size, "%s", config->host);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS))
         {
            snprintf(buffer, buffer_size, "%d", config->metrics);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_AGE))
         {
            snprintf(buffer, buffer_size, "%d", config->metrics_cache_max_age);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_CACHE_MAX_SIZE))
         {
            snprintf(buffer, buffer_size, "%zu", config->metrics_cache_max_size);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_MANAGEMENT))
         {
            snprintf(buffer, buffer_size, "%d", config->management);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BRIDGE))
         {
            snprintf(buffer, buffer_size, "%d", config->bridge);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_AGE))
         {
            snprintf(buffer, buffer_size, "%d", config->bridge_cache_max_age);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BRIDGE_CACHE_MAX_SIZE))
         {
            snprintf(buffer, buffer_size, "%zu", config->bridge_cache_max_size);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BRIDGE_JSON))
         {
            snprintf(buffer, buffer_size, "%d", config->bridge_json);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BRIDGE_JSON_CACHE_MAX_SIZE))
         {
            snprintf(buffer, buffer_size, "%zu", config->bridge_json_cache_max_size);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_CACHE))
         {
            snprintf(buffer, buffer_size, "%s", config->cache ? "true" : "false");
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_LEVEL))
         {
            snprintf(buffer, buffer_size, "%d", config->log_level);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_TYPE))
         {
            snprintf(buffer, buffer_size, "%d", config->log_type);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_PATH))
         {
            snprintf(buffer, buffer_size, "%s", config->log_path);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_MODE))
         {
            snprintf(buffer, buffer_size, "%d", config->log_mode);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_ROTATION_SIZE))
         {
            snprintf(buffer, buffer_size, "%zu", config->log_rotation_size);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_ROTATION_AGE))
         {
            snprintf(buffer, buffer_size, "%d", config->log_rotation_age);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LOG_LINE_PREFIX))
         {
            snprintf(buffer, buffer_size, "%s", config->log_line_prefix);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_TLS))
         {
            snprintf(buffer, buffer_size, "%s", config->tls ? "true" : "false");
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_TLS_CERT_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->tls_cert_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_TLS_KEY_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->tls_key_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_TLS_CA_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->tls_ca_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_CERT_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->metrics_cert_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_KEY_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->metrics_key_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_CA_FILE))
         {
            snprintf(buffer, buffer_size, "%s", config->metrics_ca_file);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BLOCKING_TIMEOUT))
         {
            snprintf(buffer, buffer_size, "%d", config->blocking_timeout);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_AUTHENTICATION_TIMEOUT))
         {
            snprintf(buffer, buffer_size, "%d", config->authentication_timeout);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_PIDFILE))
         {
            snprintf(buffer, buffer_size, "%s", config->pidfile);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_UPDATE_PROCESS_TITLE))
         {
            snprintf(buffer, buffer_size, "%u", config->update_process_title);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_LIBEV))
         {
            snprintf(buffer, buffer_size, "%s", config->libev);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_KEEP_ALIVE))
         {
            snprintf(buffer, buffer_size, "%s", config->keep_alive ? "true" : "false");
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_NODELAY))
         {
            snprintf(buffer, buffer_size, "%s", config->nodelay ? "true" : "false");
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_NON_BLOCKING))
         {
            snprintf(buffer, buffer_size, "%s", config->non_blocking ? "true" : "false");
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_BACKLOG))
         {
            snprintf(buffer, buffer_size, "%d", config->backlog);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_HUGEPAGE))
         {
            snprintf(buffer, buffer_size, "%d", config->hugepage);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_UNIX_SOCKET_DIR))
         {
            snprintf(buffer, buffer_size, "%s", config->unix_socket_dir);
         }
         else if (!strcmp(key_info.key, CONFIGURATION_ARGUMENT_METRICS_PATH))
         {
            snprintf(buffer, buffer_size, "%s", config->metrics_path);
         }
         else
         {
            pgexporter_log_debug("Unknown main configuration key: %s", key_info.key);
            return 1; // Unknown key
         }
         break;
      case 1: // Server configuration
      {
         bool server_found = false;
         for (int i = 0; i < config->number_of_servers; i++)
         {
            if (!strncmp(config->servers[i].name, key_info.context, MISC_LENGTH))
            {
               struct server* srv = &config->servers[i];
               server_found = true;
               if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_HOST))
               {
                  snprintf(buffer, buffer_size, "%s", srv->host);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_PORT))
               {
                  snprintf(buffer, buffer_size, "%d", srv->port);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_USER))
               {
                  snprintf(buffer, buffer_size, "%s", srv->username);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_DATA_DIR))
               {
                  snprintf(buffer, buffer_size, "%s", srv->data);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_WAL_DIR))
               {
                  snprintf(buffer, buffer_size, "%s", srv->wal);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_TLS_CERT_FILE))
               {
                  snprintf(buffer, buffer_size, "%s", srv->tls_cert_file);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_TLS_KEY_FILE))
               {
                  snprintf(buffer, buffer_size, "%s", srv->tls_key_file);
               }
               else if (!strcmp(key_info.key, CONFIGURATION_SERVER_ARGUMENT_TLS_CA_FILE))
               {
                  snprintf(buffer, buffer_size, "%s", srv->tls_ca_file);
               }
               else
               {
                  pgexporter_log_debug("Unknown server configuration key: %s", key_info.key);
                  return 1; // Unknown key
               }
               break;
            }
         }
         if (!server_found)
         {
            pgexporter_log_debug("Server '%s' not found", key_info.context);
            return 1;
         }
      }
      break;
      default:
         pgexporter_log_debug("Unknown section type: %d", key_info.section_type);
         return 1;
   }

   return 0;
}

