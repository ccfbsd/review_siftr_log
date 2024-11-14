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
    uint32_t max_data_sz = 0;
    uint32_t last_recovery_flags = 0;

    char plot_file_name[MAX_NAME_LENGTH];

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
    snprintf(plot_file_name, MAX_NAME_LENGTH, "plot_%u.txt", flowid);
    printf("plot_file_name: %s\n", plot_file_name);

    FILE *plot_file = fopen(plot_file_name, "w");
    if (!plot_file) {
        PERROR_FUNCTION("Failed to open plot_file for writing");
        return;
    }

    fprintf(plot_file,
            "##DIRECTION" TAB "relative_timestamp" TAB "CWND" TAB
            "SSTHRESH" TAB "snd_nxt" TAB "snd_una" TAB "pipe" TAB  "snd_cnt" TAB
            "fun_name" TAB "line" TAB "dupacks" TAB
            "INFLIGHT_BYTES" TAB "SACK_BYTES_REXMIT" TAB "SACKED_BYTES" TAB "LOST_BYTES" TAB "RECOVER_FS" TAB
            "recovery_flags(IN_RECOVERY(t_flags) | WAS_RECOVERY(t_flags))"
            "\n");

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

//            if (relative_time_stamp > 2) {
//                break;
//            }

            if (my_atol(fields[FLOW_ID]) == flowid) {
                char t_flags_arr[TF_ARRAY_MAX_LENGTH] = {0};
                char t_flags2_arr[TF2_ARRAY_MAX_LENGTH] = {0};
                uint32_t t_flags = (uint32_t)my_atol(fields[FLAG]);
                uint32_t t_flags2 = (uint32_t)my_atol(fields[FLAG2]);

                char recovery_flags_arr[TF_ARRAY_MAX_LENGTH] = {0};
                uint32_t recovery_flags = IN_RECOVERY(t_flags) | WAS_RECOVERY(t_flags);

                tcp_seq th_seq = (uint32_t)my_atol(fields[TH_SEQ]);
                tcp_seq th_ack = (uint32_t)my_atol(fields[TH_ACK]);
                uint32_t data_sz = (uint32_t)my_atol(fields[TCP_DATA_SZ]);

                if (max_data_sz < data_sz) {
                    max_data_sz = data_sz;
                }

                struct pkt_info local_pkt = {0};
                fill_pkt_info(&local_pkt, flowid, th_seq, th_ack, data_sz);

                translate_tflags(t_flags, t_flags_arr, sizeof(t_flags_arr));
                translate_tflags2(t_flags2, t_flags2_arr, sizeof(t_flags2_arr));
                translate_tflags(recovery_flags, recovery_flags_arr,
                                 sizeof(recovery_flags_arr));

                if (strcmp(fields[DIRECTION], "o") == 0) {
                    f_basics->flow_list[idx].dir_out++;
                } else {
                    f_basics->flow_list[idx].dir_in++;
                }

                fprintf(plot_file, "%s" TAB "%.6f" TAB "%s" TAB "%s" TAB //ssthresh
                        "%s" TAB "%s" TAB "%8s" TAB "%8s" TAB
                        "%21s" TAB "%4s" TAB "%3s" TAB  //dupacks
                        "%8s" TAB "%8s" TAB           //SACK_BYTES_REXMIT
                        "%8s" TAB "%8s" TAB "%8s" TAB  //RECOVER_FS
                        "%s\n",
                        fields[DIRECTION], relative_time_stamp, fields[CWND],
                        fields[SSTHRESH],
                        fields[SND_NXT], fields[SND_UNA], fields[PIPE], fields[SND_CNT],
                        fields[FUN_NAME], fields[LINE], fields[DUPACKS],
                        fields[INFLIGHT_BYTES], fields[SACK_BYTES_REXMIT],
                        fields[SACKED_BYTES], fields[LOST_BYTES], fields[RECOVER_FS],
                        recovery_flags_arr);

                if (recovery_flags == 0 && last_recovery_flags != 0) {
                    break;
                }
                last_recovery_flags = recovery_flags;
            }
        }

        lineCount++;
        /* Update the previous line to be the current line. */
        strcpy(previous_line, current_line);
    }

    if (fclose(plot_file) == EOF) {
        PERROR_FUNCTION("Failed to close plot_file");
    }

    f_basics->num_lines = lineCount;

    printf("input file has total lines: %u, max_data_sz: %u\n",
           lineCount, max_data_sz);
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
