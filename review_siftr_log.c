/*
 ============================================================================
 Name        : review_siftr_log.c
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check siftr log stats in C, Ansi-style
 ============================================================================
 */
#include <getopt.h>
#include "review_siftr_log.h"

bool verbose = false;

void
stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid)
{
    char line[MAX_LINE_LENGTH];
    char cwnd_plot_file_name[MAX_NAME_LENGTH];
    double first_flow_start_time = 0;
    double relative_time_stamp = 0;
    uint32_t current_line;

    /* Restart seeking and go back to the beginning of the file */
    fseek(f_basics->file, 0, SEEK_SET);

    current_line = 1; // Line counter (start from 1 for 1-based index)

    /* Read and discard the first line */
    if(fgets(line, MAX_LINE_LENGTH, f_basics->file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return;
    }
    current_line++; // Increment line counter, now shall be at the 2nd line

    // Combine the strings into the cwnd_plot_file buffer
    snprintf(cwnd_plot_file_name, MAX_NAME_LENGTH, "cwnd_%u.txt", flowid);
    printf("cwnd_plot_file_name: %s\n", cwnd_plot_file_name);

    FILE *cwnd_file = fopen(cwnd_plot_file_name, "w");
    if (!cwnd_file) {
        PERROR_FUNCTION("Failed to open cwnd plot file for writing");
        return;
    }

    fprintf(cwnd_file, "##DIRECTION" TAB "relative_timestamp" TAB "CWND" TAB
            "SSTHRESH\n");

    while ((fgets(line, MAX_LINE_LENGTH, f_basics->file) != NULL) &&
           (current_line != f_basics->num_lines)) {
        char *fields[TOTAL_FIELDS];

        fill_fields_from_line(fields, line);

        if (first_flow_start_time == 0) {
            first_flow_start_time = atof(fields[TIMESTAMP]);
            relative_time_stamp = 0;
        } else {
            relative_time_stamp = atof(fields[TIMESTAMP]) - first_flow_start_time;
        }

        if (my_atol(fields[FLOW_ID]) == flowid) {
            char t_flags_arr[TF_ARRAY_MAX_LENGTH] = {0};
            char t_flags2_arr[TF2_ARRAY_MAX_LENGTH] = {0};
            uint32_t t_flags = my_atol(fields[FLAG]);
            uint32_t t_flags2 = my_atol(fields[FLAG2]);

            translate_tflags(t_flags, t_flags_arr, sizeof(t_flags_arr));
            translate_tflags2(t_flags2, t_flags2_arr, sizeof(t_flags2_arr));

            fprintf(cwnd_file, "%s" TAB "%.6f" TAB "%s" TAB "%s\n",
                    fields[DIRECTION], relative_time_stamp, fields[CWND],
                    fields[SSTHRESH]);
        }
        current_line++; // Increment line counter
    }

    if (fclose(cwnd_file) == EOF) {
        PERROR_FUNCTION("Failed to close cwnd_file");
    }
}

int main(int argc, char *argv[]) {
    /* Record the start time */
    struct timeval start, end;

    gettimeofday(&start, NULL);

    struct file_basic_stats f_basics = {0};

    int opt, idx;
    int option_index = 0;
    bool option_match = false, f_opt_match = false;
    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"file", required_argument, 0, 'f'},
        {"stats", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    // Process command-line arguments
    while ((opt = getopt_long(argc, argv, "vhf:s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                verbose = option_match = true;
                printf("verbose mode enabled\n");
                break;
            case 'h':
                option_match = true;
                printf("Usage: %s [options]\n", argv[0]);
                printf(" -h, --help          Display this help message\n");
                printf(" -f, --file          Get siftr log basics\n");
                printf(" -s, --stats flowid  Get stats from flowid\n");
                printf(" -v, --verbose       Verbose mode\n");
                break;
            case 'f':
                f_opt_match = option_match = true;
                printf("input file name: %s\n", optarg);
                if (get_file_basics(&f_basics, optarg) != EXIT_SUCCESS) {
                    PERROR_FUNCTION("get_file_basics() failed");
                    return EXIT_FAILURE;
                }
                show_file_basic_stats(&f_basics);
                break;
            case 's':
                option_match = true;
                printf("input flow id is: %s", optarg);
                if (!f_opt_match) {
                    printf(", but no data file is given\n");
                    return EXIT_FAILURE;
                } else {
                    printf("\n");
                }
                uint32_t flowid = (uint32_t)my_atol(optarg);
                if (is_flowid_in_file(&f_basics, flowid, &idx)) {
                    read_body_by_flowid(&f_basics, flowid);
                } else {
                    printf("flow ID %u not found\n", flowid);
                }
                break;
            default:
                printf("Usage: %s [-v | h] [-f file_name] [-s flow_id]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Handle case where no options are provided or non-option arguments */
    if (!option_match) {
        printf("Un-expected argument!\n");
        printf("Usage: %s [-v] [-h] [-f file_name] [-s flow_id]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (option_match && !f_opt_match) {
        return EXIT_SUCCESS;
    }

    if (cleanup_file_basic_stats(&f_basics) != EXIT_SUCCESS) {
        PERROR_FUNCTION("terminate_file_basics() failed");
    }

    // Record the end time
    gettimeofday(&end, NULL);
    // Calculate the time taken in seconds and microseconds
    double seconds = (end.tv_sec - start.tv_sec);
    double micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    printf("\nthis program execution time: %.3f seconds\n", micros / 1000000.0);

    return EXIT_SUCCESS;
}
