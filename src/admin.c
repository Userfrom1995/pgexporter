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
#include <logging.h>
#include <management.h>
#include <security.h>
#include <utils.h>

/* system */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_PASSWORD_LENGTH 64

static char CHARS[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                       'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                       '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                       '!', '@', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', '{', ']', '}', '\\', '|', ':',
                       '\'', '\"', ',', '<', '.', '>', '/', '?'};

static int master_key(char* password, bool generate_pwd, int pwd_length, int32_t output_format);
static bool is_valid_key(char* key);
static int add_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format);
static int update_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format);
static int remove_user(char* users_path, char* username, int32_t output_format);
static int list_users(char* users_path, int32_t output_format);
static char* generate_password(int pwd_length);
static int create_response(char* users_path, struct json* json, struct json** response);

const struct pgexporter_command command_table[] =
{
   {
      .command = "master-key",
      .subcommand = "",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_MASTER_KEY,
      .log_message = "<master-key>",
   },
   {
      .command = "user",
      .subcommand = "add",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_ADD_USER,
      .log_message = "<user add> [%s]",
   },
   {
      .command = "user",
      .subcommand = "edit",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_UPDATE_USER,
      .log_message = "<user edit> [%s]",
   },
   {
      .command = "user",
      .subcommand = "del",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_REMOVE_USER,
      .log_message = "<user del> [%s]",
   },
   {
      .command = "user",
      .subcommand = "ls",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_LIST_USERS,
      .log_message = "<user ls>",
   },
};

static void
version(void)
{
   printf("pgexporter-admin %s\n", VERSION);
   exit(1);
}

static void
usage(void)
{
   printf("pgexporter-admin %s\n", VERSION);
   printf("  Administration utility for pgexporter\n");
   printf("\n");

   printf("Usage:\n");
   printf("  pgexporter-admin [ -f FILE ] [ COMMAND ] \n");
   printf("\n");
   printf("Options:\n");
   printf("  -f, --file FILE         Set the path to a user file\n");
   printf("  -U, --user USER         Set the user name\n");
   printf("  -P, --password PASSWORD Set the password for the user\n");
   printf("  -g, --generate          Generate a password\n");
   printf("  -l, --length            Password length\n");
   printf("  -V, --version           Display version information\n");
   printf("  -F, --format text|json  Set the output format\n");
   printf("  -?, --help              Display help\n");
   printf("\n");
   printf("Commands:\n");
   printf("  master-key              Create or update the master key\n");
   printf("  user <subcommand>       Manage a specific user, where <subcommand> can be\n");
   printf("                          - add  to add a new user\n");
   printf("                          - del  to remove an existing user\n");
   printf("                          - edit to change the password for an existing user\n");
   printf("                          - ls   to list all available users\n");
   printf("\n");
   printf("pgexporter: %s\n", PGEXPORTER_HOMEPAGE);
   printf("Report bugs: %s\n", PGEXPORTER_ISSUES);
}

int
main(int argc, char** argv)
{
   int c;
   char* username = NULL;
   char* password = NULL;
   char* file_path = NULL;
   bool generate_pwd = false;
   int pwd_length = DEFAULT_PASSWORD_LENGTH;
   int option_index = 0;
   size_t command_count = sizeof(command_table) / sizeof(struct pgexporter_command);
   struct pgexporter_parsed_command parsed = {.cmd = NULL, .args = {0}};
   int32_t output_format = MANAGEMENT_OUTPUT_FORMAT_TEXT;

   // Disable stdout buffering (i.e. write to stdout immediatelly).
   setbuf(stdout, NULL);

   while (1)
   {
      static struct option long_options[] =
      {
         {"user", required_argument, 0, 'U'},
         {"password", required_argument, 0, 'P'},
         {"file", required_argument, 0, 'f'},
         {"generate", no_argument, 0, 'g'},
         {"length", required_argument, 0, 'l'},
         {"format", required_argument, 0, 'F'},
         {"version", no_argument, 0, 'V'},
         {"help", no_argument, 0, '?'}
      };

      c = getopt_long(argc, argv, "gV?f:U:P:l:F:",
                      long_options, &option_index);

      if (c == -1)
      {
         break;
      }

      switch (c)
      {
         case 'U':
            username = optarg;
            break;
         case 'P':
            password = optarg;
            break;
         case 'f':
            file_path = optarg;
            break;
         case 'g':
            generate_pwd = true;
            break;
         case 'l':
            pwd_length = atoi(optarg);
            break;
         case 'V':
            version();
            break;
         case 'F':
            if (!strncmp(optarg, "json", MISC_LENGTH))
            {
               output_format = MANAGEMENT_OUTPUT_FORMAT_JSON;
            }
            else if (!strncmp(optarg, "text", MISC_LENGTH))
            {
               output_format = MANAGEMENT_OUTPUT_FORMAT_TEXT;
            }
            else
            {
               warnx("pgexporter-cli: Format type is not correct");
               exit(1);
            }
            break;
         case '?':
            usage();
            exit(1);
            break;
         default:
            break;
      }
   }

   if (getuid() == 0)
   {
      errx(1, "pgexporter: Using the root account is not allowed");
   }

   if (!parse_command(argc, argv, optind, &parsed, command_table, command_count))
   {
      usage();
      goto error;
   }

   if (parsed.cmd->action == MANAGEMENT_MASTER_KEY)
   {
      if (master_key(password, generate_pwd, pwd_length, output_format))
      {
         errx(1, "Cannot generate master key");
      }
   }
   else
   {
      if (file_path == NULL)
      {
         errx(1, "Missing file argument");
      }

      if (parsed.cmd->action == MANAGEMENT_ADD_USER)
      {
         if (add_user(file_path, username, password, generate_pwd, pwd_length, output_format))
         {
            errx(1, "Error for <user add>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_UPDATE_USER)
      {
         if (update_user(file_path, username, password, generate_pwd, pwd_length, output_format))
         {
            errx(1, "Error for <user edit>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_REMOVE_USER)
      {

         if (remove_user(file_path, username, output_format))
         {
            errx(1, "Error for <user del>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_LIST_USERS)
      {

         if (list_users(file_path, output_format))
         {
            errx(1, "Error for <user ls>");
         }

      }
   }

   exit(0);

error:

   exit(1);
}

static int
master_key(char* password, bool generate_pwd, int pwd_length, int32_t output_format)
{
   FILE* file = NULL;
   char buf[MISC_LENGTH];
   char* encoded = NULL;
   size_t encoded_length;
   struct stat st = {0};
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   time_t start_t;
   time_t end_t;

   start_t = time(NULL);

   if (pgexporter_management_create_header(MANAGEMENT_MASTER_KEY, 0, 0, output_format, &j))
   {
      goto error;
   }

   if (password != NULL)
   {
      do_free = false;
   }

   if (pgexporter_get_home_directory() == NULL)
   {
      char* username = pgexporter_get_user_name();

      if (username != NULL)
      {
         warnx("No home directory for user \'%s\'", username);
      }
      else
      {
         warnx("No home directory for user running pgexporter");
      }

      goto error;
   }

   memset(&buf, 0, sizeof(buf));
   snprintf(&buf[0], sizeof(buf), "%s/.pgexporter", pgexporter_get_home_directory());

   if (stat(&buf[0], &st) == -1)
   {
      mkdir(&buf[0], S_IRWXU);
   }
   else
   {
      if (S_ISDIR(st.st_mode) && st.st_mode & S_IRWXU && !(st.st_mode & S_IRWXG) && !(st.st_mode & S_IRWXO))
      {
         /* Ok */
      }
      else
      {
         warnx("Wrong permissions for ~/.pgexporter (must be 0700)");
         goto error;
      }
   }

   memset(&buf, 0, sizeof(buf));
   snprintf(&buf[0], sizeof(buf), "%s/.pgexporter/master.key", pgexporter_get_home_directory());

   if (pgexporter_exists(&buf[0]))
   {
      warnx("The file ~/.pgexporter/master.key already exists");
      goto error;
   }

   if (stat(&buf[0], &st) == -1)
   {
      /* Ok */
   }
   else
   {
      if (S_ISREG(st.st_mode) && st.st_mode & (S_IRUSR | S_IWUSR) && !(st.st_mode & S_IRWXG) && !(st.st_mode & S_IRWXO))
      {
         /* Ok */
      }
      else
      {
         warnx("Wrong permissions for ~/.pgexporter/master.key (must be 0600)");
         goto error;
      }
   }

   file = fopen(&buf[0], "w+");
   if (file == NULL)
   {
      warn("Could not write to master key file '%s'", &buf[0]);
      goto error;
   }

   if (password == NULL)
   {
      if (!generate_pwd)
      {
         while (!is_valid_key(password))
         {
            if (password != NULL)
            {
               free(password);
               password = NULL;
            }

            printf("Master key: ");
            password = pgexporter_get_password();
            printf("\n");
         }
      }
      else
      {
         password = generate_password(pwd_length);
         do_free = false;
      }
   }
   else
   {
      do_free = false;

      if (!is_valid_key(password))
      {
         goto error;
      }
   }

   end_t = time(NULL);

   if (pgexporter_management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_base64_encode(password, strlen(password), &encoded, &encoded_length);
   fputs(encoded, file);
   free(encoded);

   pgexporter_json_destroy(j);

   if (do_free)
   {
      free(password);
   }

   fclose(file);

   chmod(&buf[0], S_IRUSR | S_IWUSR);

   return 0;

error:

   free(encoded);

   if (do_free)
   {
      free(password);
   }

   if (file)
   {
      fclose(file);
   }

   return 1;
}

static bool
is_valid_key(char* key)
{
   char c;

   if (!key)
   {
      return false;
   }

   if (strlen(key) < 8)
   {
      warnx("Master key must be at least 8 characters long");
      return false;
   }

   for (size_t i = 0; i < strlen(key); i++)
   {
      c = *(key + i);

      /* Only support ASCII for now */
      if ((unsigned char)c & 0x80)
      {
         warnx("Master key cannot contain non-ASCII characters");
         return false;
      }
   }

   return true;
}

static int
add_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format)
{
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* entry = NULL;
   char* master_key = NULL;
   char* ptr = NULL;
   char* encrypted = NULL;
   int encrypted_length = 0;
   char* encoded = NULL;
   size_t encoded_length;
   char un[MAX_USERNAME_LENGTH];
   int number_of_users = 0;
   bool do_verify = true;
   char* verify = NULL;
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   time_t start_t;
   time_t end_t;

   start_t = time(NULL);

   if (pgexporter_management_create_header(MANAGEMENT_ADD_USER, 0, 0, output_format, &j))
   {
      goto error;
   }

   if (pgexporter_get_master_key(&master_key))
   {
      warnx("Invalid master key");
      goto error;
   }

   if (password != NULL)
   {
      do_verify = false;
      do_free = false;
   }

   users_file = fopen(users_path, "a+");
   if (users_file == NULL)
   {
      warn("Could not append to users file '%s'", users_path);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Verify */
   while (fgets(line, sizeof(line), users_file))
   {
      ptr = strtok(line, ":");
      if (!strcmp(username, ptr))
      {
         warnx("Existing user: %s", username);
         goto error;
      }

      number_of_users++;
   }

   if (number_of_users > NUMBER_OF_USERS)
   {
      warnx("Too many users");
      goto error;
   }

   /* Password */
   if (password == NULL)
   {
password:
      if (generate_pwd)
      {
         password = generate_password(pwd_length);
         do_verify = false;
         printf("Password : %s", password);
      }
      else
      {
         printf("Password : ");

         if (password != NULL)
         {
            free(password);
            password = NULL;
         }

         password = pgexporter_get_password();
      }
      printf("\n");
   }

   for (size_t i = 0; i < strlen(password); i++)
   {
      if ((unsigned char)(*(password + i)) & 0x80)
      {
         goto password;
      }
   }

   if (do_verify)
   {
      printf("Verify   : ");

      if (verify != NULL)
      {
         free(verify);
         verify = NULL;
      }

      verify = pgexporter_get_password();
      printf("\n");

      if (strlen(password) != strlen(verify) || memcmp(password, verify, strlen(password)) != 0)
      {
         goto password;
      }
   }

   pgexporter_encrypt(password, master_key, &encrypted, &encrypted_length, ENCRYPTION_AES_256_CBC);
   pgexporter_base64_encode(encrypted, encrypted_length, &encoded, &encoded_length);

   entry = pgexporter_append(entry, username);
   entry = pgexporter_append(entry, ":");
   entry = pgexporter_append(entry, encoded);
   entry = pgexporter_append(entry, "\n");

   fputs(entry, users_file);

   free(entry);
   free(master_key);
   free(encrypted);
   free(encoded);
   if (do_free)
   {
      free(password);
   }
   free(verify);

   fclose(users_file);

   end_t = time(NULL);

   if (pgexporter_management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 0;

error:

   free(entry);
   free(master_key);
   free(encrypted);
   free(encoded);
   if (do_free)
   {
      free(password);
   }
   free(verify);

   if (users_file)
   {
      fclose(users_file);
   }

   pgexporter_management_create_outcome_failure(j, 1, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 1;
}

static int
update_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format)
{
   FILE* users_file = NULL;
   FILE* users_file_tmp = NULL;
   char tmpfilename[MISC_LENGTH];
   char line[MISC_LENGTH];
   char line_copy[MISC_LENGTH];
   char* entry = NULL;
   char* master_key = NULL;
   char* ptr = NULL;
   char* encrypted = NULL;
   int encrypted_length = 0;
   char* encoded = NULL;
   size_t encoded_length;
   char un[MAX_USERNAME_LENGTH];
   bool found = false;
   bool do_verify = true;
   char* verify = NULL;
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   time_t start_t;
   time_t end_t;

   start_t = time(NULL);

   if (pgexporter_management_create_header(MANAGEMENT_UPDATE_USER, 0, 0, output_format, &j))
   {
      goto error;
   }

   memset(&tmpfilename, 0, sizeof(tmpfilename));

   if (pgexporter_get_master_key(&master_key))
   {
      warnx("Invalid master key");
      goto error;
   }

   if (password != NULL)
   {
      do_verify = false;
      do_free = false;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      warnx("%s not found\n", users_path);
      goto error;
   }

   snprintf(tmpfilename, sizeof(tmpfilename), "%s.tmp", users_path);
   users_file_tmp = fopen(tmpfilename, "w+");
   if (users_file_tmp == NULL)
   {
      warn("Could not write to temporary user file '%s'", tmpfilename);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Update */
   while (fgets(line, sizeof(line), users_file))
   {
      memset(&line_copy, 0, sizeof(line_copy));
      memcpy(&line_copy, &line, strlen(line));

      ptr = strtok(line, ":");
      if (!strcmp(username, ptr))
      {
         /* Password */
         if (password == NULL)
         {
password:
            if (generate_pwd)
            {
               password = generate_password(pwd_length);
               do_verify = false;
               printf("Password : %s", password);
            }
            else
            {
               printf("Password : ");

               if (password != NULL)
               {
                  free(password);
                  password = NULL;
               }

               password = pgexporter_get_password();
            }
            printf("\n");
         }

         for (size_t i = 0; i < strlen(password); i++)
         {
            if ((unsigned char)(*(password + i)) & 0x80)
            {
               goto password;
            }
         }

         if (do_verify)
         {
            printf("Verify   : ");

            if (verify != NULL)
            {
               free(verify);
               verify = NULL;
            }

            verify = pgexporter_get_password();
            printf("\n");

            if (strlen(password) != strlen(verify) || memcmp(password, verify, strlen(password)) != 0)
            {
               goto password;
            }
         }

         pgexporter_encrypt(password, master_key, &encrypted, &encrypted_length, ENCRYPTION_AES_256_CBC);
         pgexporter_base64_encode(encrypted, encrypted_length, &encoded, &encoded_length);

         memset(&line, 0, sizeof(line));
         entry = NULL;
         entry = pgexporter_append(entry, username);
         entry = pgexporter_append(entry, ":");
         entry = pgexporter_append(entry, encoded);
         entry = pgexporter_append(entry, "\n");

         fputs(entry, users_file_tmp);
         free(entry);

         found = true;
      }
      else
      {
         fputs(line_copy, users_file_tmp);
      }
   }

   if (!found)
   {
      warnx("User '%s' not found", username);
      goto error;
   }

   free(master_key);
   free(encrypted);
   free(encoded);
   if (do_free)
   {
      free(password);
   }
   free(verify);

   fclose(users_file);
   fclose(users_file_tmp);

   rename(tmpfilename, users_path);

   end_t = time(NULL);

   if (pgexporter_management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 0;

error:

   free(master_key);
   free(encrypted);
   free(encoded);
   if (do_free)
   {
      free(password);
   }
   free(verify);

   if (users_file)
   {
      fclose(users_file);
   }

   if (users_file_tmp)
   {
      fclose(users_file_tmp);
   }

   if (strlen(tmpfilename) > 0)
   {
      remove(tmpfilename);
   }

   pgexporter_management_create_outcome_failure(j, 1, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 1;
}

static int
remove_user(char* users_path, char* username, int32_t output_format)
{
   FILE* users_file = NULL;
   FILE* users_file_tmp = NULL;
   char tmpfilename[MISC_LENGTH];
   char line[MISC_LENGTH];
   char line_copy[MISC_LENGTH];
   char* ptr = NULL;
   char un[MAX_USERNAME_LENGTH];
   bool found = false;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   time_t start_t;
   time_t end_t;

   start_t = time(NULL);

   if (pgexporter_management_create_header(MANAGEMENT_REMOVE_USER, 0, 0, output_format, &j))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      warnx("%s not found", users_path);
      goto error;
   }

   memset(&tmpfilename, 0, sizeof(tmpfilename));
   snprintf(tmpfilename, sizeof(tmpfilename), "%s.tmp", users_path);
   users_file_tmp = fopen(tmpfilename, "w+");
   if (users_file_tmp == NULL)
   {
      warn("Could not write to temporary user file '%s'", tmpfilename);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Remove */
   while (fgets(line, sizeof(line), users_file))
   {
      memset(&line_copy, 0, sizeof(line_copy));
      memcpy(&line_copy, &line, strlen(line));

      ptr = strtok(line, ":");
      if (!strcmp(username, ptr))
      {
         found = true;
      }
      else
      {
         fputs(line_copy, users_file_tmp);
      }
   }

   if (!found)
   {
      warnx("User '%s' not found", username);
      goto error;
   }

   fclose(users_file);
   fclose(users_file_tmp);

   rename(tmpfilename, users_path);

   end_t = time(NULL);

   if (pgexporter_management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 0;

error:

   if (users_file)
   {
      fclose(users_file);
   }

   if (users_file_tmp)
   {
      fclose(users_file_tmp);
   }

   if (strlen(tmpfilename) > 0)
   {
      remove(tmpfilename);
   }

   pgexporter_management_create_outcome_failure(j, 1, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 1;
}

static int
list_users(char* users_path, int32_t output_format)
{
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* ptr = NULL;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   time_t start_t;
   time_t end_t;

   start_t = time(NULL);

   if (pgexporter_management_create_header(MANAGEMENT_LIST_USERS, 0, 0, output_format, &j))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      goto error;
   }

   /* List */
   while (fgets(line, sizeof(line), users_file))
   {
      ptr = strtok(line, ":");
      if (strchr(ptr, '\n'))
      {
         continue;
      }
      printf("%s\n", ptr);
   }

   fclose(users_file);

   end_t = time(NULL);

   if (pgexporter_management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 0;

error:

   if (users_file)
   {
      fclose(users_file);
   }

   pgexporter_management_create_outcome_failure(j, 1, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgexporter_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgexporter_json_print(j, FORMAT_TEXT);
   }

   pgexporter_json_destroy(j);

   return 1;
}

static char*
generate_password(int pwd_length)
{
   char* pwd;
   size_t s;
   time_t t;

   s = pwd_length + 1;

   pwd = malloc(s);
   memset(pwd, 0, s);

   srand((unsigned)time(&t));

   for (size_t i = 0; i < s; i++)
   {
      *((char*)(pwd + i)) = CHARS[rand() % sizeof(CHARS)];
   }
   *((char*)(pwd + pwd_length)) = '\0';

   return pwd;
}

static int
create_response(char* users_path, struct json* json, struct json** response)
{
   struct json* r = NULL;
   struct json* users = NULL;
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* ptr = NULL;

   *response = NULL;

   if (pgexporter_json_create(&r))
   {
      goto error;
   }

   pgexporter_json_put(json, MANAGEMENT_CATEGORY_RESPONSE, (uintptr_t)r, ValueJSON);

   if (pgexporter_json_create(&users))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      goto error;
   }

   while (fgets(line, sizeof(line), users_file))
   {
      ptr = strtok(line, ":");
      if (strchr(ptr, '\n'))
      {
         continue;
      }
      pgexporter_json_append(users, (uintptr_t)ptr, ValueString);
   }

   pgexporter_json_put(r, "Users", (uintptr_t)users, ValueJSON);

   *response = r;

   return 0;

error:

   pgexporter_json_destroy(r);

   return 1;
}