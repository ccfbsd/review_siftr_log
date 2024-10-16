/*
 ============================================================================
 Name        : review_siftr_log.c
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check siftr log stats in C, Ansi-style
 ============================================================================
 */
#include "review_siftr2_log.h"

#include <getopt.h>

bool verbose = false;

void
stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid)
{
    uint32_t lineCount = 0;
    char current_line[MAX_LINE_LENGTH];
    char previous_line[MAX_LINE_LENGTH] = {0};

    double first_flow_start_time = 0;
    double relative_time_stamp = 0;

    char cwnd_plot_file_name[MAX_NAME_LENGTH];

    int idx;

    if (!is_flowid_in_file(f_basics, flowid, &idx)) {
        printf("%s:%u: flow ID %u not found\n", __FUNCTION__, __LINE__, flowid);
        PERROR_FUNCTION("Failed to open sack plot file for writing");
        return;
    }
    assert((0 == f_basics->flow_list[idx].dir_in) &&
           (0 == f_basics->flow_list[idx].dir_out));

    /* Restart seeking and go back to the beginning of the file */
    fseek(f_basics->file, 0, SEEK_SET);

    /* Read and discard the first line */
    if(fgets(current_line, MAX_LINE_LENGTH, f_basics->file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return;
    }
    lineCount++; // Increment line counter, now shall be at the 2nd line

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

    while (fgets(current_line, MAX_LINE_LENGTH, f_basics->file) != NULL) {
        if (previous_line[0] != '\0') {
            char *fields[TOTAL_FIELDS];

            fill_fields_from_line(fields, previous_line, BODY);

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

                if (strcmp(fields[DIRECTION], "o") == 0) {
                    f_basics->flow_list[idx].dir_out++;
                } else {
                    f_basics->flow_list[idx].dir_in++;
                }

                fprintf(cwnd_file, "%s" TAB "%.6f" TAB "%s" TAB "%s\n",
                        fields[DIRECTION], relative_time_stamp, fields[CWND],
                        fields[SSTHRESH]);
            }
        }

        lineCount++;
        /* Update the previous line to be the current line. */
        strcpy(previous_line, current_line);
    }

    if (fclose(cwnd_file) == EOF) {
        PERROR_FUNCTION("Failed to close cwnd_file");
    }

    f_basics->num_lines = lineCount;

    if (verbose) {
        printf("input file has total lines: %u\n", lineCount);
    }
}

int main(int argc, char *argv[]) {
    /* Record the start time */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    struct file_basic_stats f_basics = {0};

    int opt;
    int opt_idx = 0;
    bool opt_match = false, f_opt_match = false;
    struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"file", required_argument, 0, 'f'},
        {"stats", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    // Process command-line arguments
    while ((opt = getopt_long(argc, argv, "vhf:s:", long_opts, &opt_idx)) != -1) {
        switch (opt) {
            case 'v':
                verbose = opt_match = true;
                printf("verbose mode enabled\n");
                break;
            case 'h':
                opt_match = true;
                printf("Usage: %s [options]\n", argv[0]);
                printf(" -h, --help          Display this help message\n");
                printf(" -f, --file          Get siftr log basics\n");
                printf(" -s, --stats flowid  Get stats from flowid\n");
                printf(" -v, --verbose       Verbose mode\n");
                break;
            case 'f':
                f_opt_match = opt_match = true;
                printf("input file name: %s\n", optarg);
                if (get_file_basics(&f_basics, optarg) != EXIT_SUCCESS) {
                    PERROR_FUNCTION("get_file_basics() failed");
                    return EXIT_FAILURE;
                }
                show_file_basic_stats(&f_basics);
                break;
            case 's':
                opt_match = true;
                printf("input flow id is: %s", optarg);
                if (!f_opt_match) {
                    printf(", but no data file is given\n");
                    return EXIT_FAILURE;
                } else {
                    printf("\n");
                }
                read_body_by_flowid(&f_basics, my_atol(optarg));
                break;
            default:
                printf("Usage: %s [-v | -h] [-f file_name] [-s flow_id]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Handle case where no options are provided or non-option arguments */
    if (!opt_match) {
        printf("Un-expected argument!\n");
        printf("Usage: %s [-v | -h] [-f file_name] [-s flow_id]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_match && !f_opt_match) {
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
