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
stats_into_plot_file(file_basic_stats_t *f_basics, uint32_t flowid)
{
    uint32_t lineCount = 0;
    char current_line[MAX_LINE_LENGTH];
    char previous_line[MAX_LINE_LENGTH] = {0};

    double first_flow_start_time = 0;
    double relative_time_stamp = 0;

    char sack_plot_file_name[MAX_NAME_LENGTH];
    long int max_tp_sack_cnt = 0;
    long int max_to_sack_cnt = 0;

    /* Restart seeking and go back to the beginning of the file */
    fseek(f_basics->file, 0, SEEK_SET);

    /* Read and discard the first line */
    if(fgets(current_line, MAX_LINE_LENGTH, f_basics->file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return;
    }
    lineCount++; // Increment line counter, now shall be at the 2nd line

    // Combine the strings into the sack_plot_file_name buffer
    snprintf(sack_plot_file_name, MAX_NAME_LENGTH, "sack_%u.txt", flowid);
    printf("sack_plot_file_name: %s\n", sack_plot_file_name);

    FILE *sack_file = fopen(sack_plot_file_name, "w");
    if (!sack_file) {
        PERROR_FUNCTION("Failed to open sack plot file for writing");
        return;
    }

    fprintf(sack_file, "##DIRECTION" TAB "relative_timestamp" TAB "th_seq" TAB
            "th_ack" TAB "data_sz" TAB
            "tp_nsacks" TAB "tp_sackblks[0]" TAB "tp_sackblks[1]" TAB "tp_sackblks[2]"
            "to_nsacks" TAB "to_sackblks[0]" TAB "to_sackblks[1]" TAB "to_sackblks[2]"
            "\n");

    while (fgets(current_line, MAX_LINE_LENGTH, f_basics->file) != NULL) {
        if (previous_line[0] != '\0') {
            char *fields[TOTAL_FIELDS];

            fill_fields_from_line(fields, previous_line, BODY);

            long int tp_nsacks = my_atol(fields[TP_NSACKS]);
            long int to_nsacks = my_atol(fields[TO_NSACKS]);

            if (first_flow_start_time == 0) {
                first_flow_start_time = atof(fields[TIMESTAMP]);
                relative_time_stamp = 0;
            } else {
                relative_time_stamp = atof(fields[TIMESTAMP]) - first_flow_start_time;
            }

            if (my_atol(fields[FLOW_ID]) == flowid &&
                (to_nsacks > 0 || tp_nsacks > 0)) {
                char t_flags_arr[TF_ARRAY_MAX_LENGTH] = {0};
                char t_flags2_arr[TF2_ARRAY_MAX_LENGTH] = {0};
                uint32_t t_flags = my_atol(fields[FLAG]);
                uint32_t t_flags2 = my_atol(fields[FLAG2]);

                translate_tflags(t_flags, t_flags_arr, sizeof(t_flags_arr));
                translate_tflags2(t_flags2, t_flags2_arr, sizeof(t_flags2_arr));

                if (max_tp_sack_cnt < tp_nsacks) {
                    max_tp_sack_cnt = tp_nsacks;
                }
                if (max_to_sack_cnt < to_nsacks) {
                    max_to_sack_cnt = to_nsacks;
                }

                fprintf(sack_file,
                        "%s" TAB "%.6f" TAB "%s" TAB "%s" TAB "%s" TAB
                        "%s" TAB "(%s,%s)" TAB "(%s,%s)" TAB "(%s,%s)" TAB
                        "%s" TAB "(%s,%s)" TAB "(%s,%s)" TAB "(%s,%s)" TAB
                        "\n",
                        fields[DIRECTION], relative_time_stamp, fields[TH_SEQ],
                        fields[TH_ACK], fields[TCP_DATA_SZ],
                        fields[TP_NSACKS],
                        fields[TP_SACKBLKS0_S], fields[TP_SACKBLKS0_E],
                        fields[TP_SACKBLKS1_S], fields[TP_SACKBLKS1_E],
                        fields[TP_SACKBLKS2_S], fields[TP_SACKBLKS2_E],
                        fields[TO_NSACKS],
                        fields[TO_SACKBLKS0_S], fields[TO_SACKBLKS0_E],
                        fields[TO_SACKBLKS1_S], fields[TO_SACKBLKS1_E],
                        fields[TO_SACKBLKS2_S], fields[TO_SACKBLKS2_E]);
            }
            if (tp_nsacks > 3) {
                PERROR_FUNCTION("fields[TP_NSACKS] > 3");
            }
            if (to_nsacks > 3) {
                PERROR_FUNCTION("fields[TO_NSACKS] > 3");
            }
        }

        lineCount++;
        /* Update the previous line to be the current line. */
        strcpy(previous_line, current_line);
    }

    if (fclose(sack_file) == EOF) {
        PERROR_FUNCTION("Failed to close sack_file");
    }

    f_basics->num_lines = lineCount;

    if (verbose) {
        printf("input file has total lines: %u\n", lineCount);
        printf("max_tp_sack_cnt: %ld, max_to_sack_cnt: %ld\n",
                max_tp_sack_cnt, max_to_sack_cnt);
    }
}

int main(int argc, char *argv[]) {
    /* Record the start time */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    file_basic_stats_t f_basics = {0};

    int opt;
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
                read_body_by_flowid(&f_basics, my_atol(optarg));
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
