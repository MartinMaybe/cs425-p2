#include "cli.h"
#include "transfer.h"

#include <stdio.h>

#ifdef TEST
#define main main_exclude
#endif



int main(int argc, char *argv[])
{
    cli_options options;
    char error[256];
    cli_parse_result result;

    if (argc == 1) {
        print_usage(stdout);
        return 0;
    }

    result = parse_cli(argc, argv, &options, error, sizeof(error));
    if (result == CLI_PARSE_INVALID) {
        (void)fprintf(stderr, "%s\n", error);
        print_usage(stderr);
        return 1;
    }
    if (result == CLI_PARSE_RESOLUTION_ERROR) {
        (void)fprintf(stderr, "%s\n", error);
        return 2;
    }

    if (options.mode == TRANSFER_RECEIVE) {
        int status = receive_transfer(&options);
        free_cli_options(&options);
        return status;
    }

    (void)fprintf(stderr, "Sender is not implemented yet.\n");
    free_cli_options(&options);
    return 2;
}