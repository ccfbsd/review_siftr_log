/*
 ============================================================================
 Name        : review_siftr_log.h
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check siftr log stats in C, Ansi-style
 ============================================================================
 */

#ifndef REVIEW_SIFTR_LOG_H_
#define REVIEW_SIFTR_LOG_H_

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

enum {
    INP_IPV4 = 0x1, INP_IPV6 = 0x2,
    MAX_LINE_LENGTH = 1000,
    MAX_NAME_LENGTH = 100,
    INET6_ADDRSTRLEN = 46,
    TF_ARRAY_MAX_LENGTH = 550,
    TF2_ARRAY_MAX_LENGTH = 560,
    PER_FLOW_STRING_LENGTH = (INET6_ADDRSTRLEN*2 + 5*2 + 1),
};

#define COMMA_DELIMITER     ","
#define TAB_DELIMITER       "\t"
#define TAB         TAB_DELIMITER
#define EQUAL_DELIMITER     "="

#define PERROR_FUNCTION(msg) \
        do {                                                                \
            fprintf(stderr, "Error in %s:%s:%u ",                           \
                    __FILE__, __FUNCTION__, __LINE__);                      \
            perror(msg);                                                    \
        } while(0)

#define GET_VALUE(field) \
        my_atol(next_sub_str_from(field, EQUAL_DELIMITER));

enum {
    ENABLE_TIME_SECS,
    ENABLE_TIME_USECS,
    SIFTRVER,
    SYSNAME,
    SYSVER,
    IPMODE,
    HZ,
    TOTAL_FIRST_LINE_FIELDS,
};

struct first_line_fields {
    char        siftrver[8];
    char        sysname[8];
    char        sysver[8];
    char        ipmode[8];
    struct timeval enable_time;
};

enum {
    DISABLE_TIME_SECS,
    DISABLE_TIME_USECS,
    NUM_INBOUND_TCP_PKTS,
    NUM_OUTBOUND_TCP_PKTS,
    TOTAL_TCP_PKTS,
    NUM_INBOUND_SKIPPED_PKTS_MALLOC,
    NUM_OUTBOUND_SKIPPED_PKTS_MALLOC,
    NUM_INBOUND_SKIPPED_PKTS_TCPCB,
    NUM_OUTBOUND_SKIPPED_PKTS_TCPCB,
    NUM_INBOUND_SKIPPED_PKTS_INPCB,
    NUM_OUTBOUND_SKIPPED_PKTS_INPCB,
    TOTAL_SKIPPED_TCP_PKTS,
    FLOWID_LIST,
    TOTAL_LAST_LINE_FIELDS,
};

struct last_line_fields {
    uint64_t    num_inbound_tcp_pkts;
    uint64_t    num_outbound_tcp_pkts;
    uint64_t    total_tcp_pkts;
    uint32_t    num_inbound_skipped_pkts_malloc;
    uint32_t    num_outbound_skipped_pkts_malloc;
    uint32_t    num_inbound_skipped_pkts_tcpcb;
    uint32_t    num_outbound_skipped_pkts_tcpcb;
    uint32_t    num_inbound_skipped_pkts_inpcb;
    uint32_t    num_outbound_skipped_pkts_inpcb;
    uint32_t    total_skipped_tcp_pkts;
    char        *flowid_list;
    struct timeval disable_time;
};

enum {
    DIRECTION,  TIMESTAMP,  LOIP,   LPORT,  FOIP,   FPORT,
    SSTHRESH,   CWND,       FLAG2,  SNDWIN, RCVWIN, SNDSCALE,
    RCVSCALE,   STATE,      MSS,    SRTT,   ISSACK, FLAG,   RTO,
    SND_BUF_HIWAT,          SND_BUF_CC,     RCV_BUF_HIWAT,  RCV_BUF_CC,
    INFLIGHT_BYTES,         REASS_QLEN,     FLOW_ID,        FLOW_TYPE,
    TOTAL_FIELDS,
};

struct flow_info {
    char        laddr[INET6_ADDRSTRLEN];    /* local IP address */
    char        faddr[INET6_ADDRSTRLEN];    /* foreign IP address */
    uint16_t    lport;                  /* local TCP port */
    uint16_t    fport;                  /* foreign TCP port */
    uint8_t     ipver;                  /* IP version */
    uint32_t    flowid;                 /* flowid of the connection */
    uint32_t    record_cnt;
    bool        is_info_set;
};

struct file_basic_stats {
    FILE                    *file;
    uint32_t                num_lines;
    uint32_t                flow_count;
    struct flow_info        *flow_list;
    struct first_line_fields *first_line_stats;
    struct last_line_fields  *last_line_stats;
};

/* Flags for the tp->t_flags field. */
enum {
    TF_ACKNOW = 0x00000001, TF_DELACK = 0x00000002, TF_NODELAY = 0x00000004,
    TF_NOOPT = 0x00000008,  TF_SENTFIN = 0x00000010, TF_REQ_SCALE = 0x00000020,
    TF_RCVD_SCALE = 0x00000040, TF_REQ_TSTMP = 0x00000080,
    TF_RCVD_TSTMP = 0x00000100, TF_SACK_PERMIT = 0x00000200,
    TF_NEEDSYN = 0x00000400, TF_NEEDFIN = 0x00000800, TF_NOPUSH = 0x00001000,
    TF_PREVVALID = 0x00002000, TF_WAKESOR = 0x00004000,
    TF_GPUTINPROG = 0x00008000, TF_MORETOCOME = 0x00010000,
    TF_SONOTCONN = 0x00020000, TF_LASTIDLE = 0x00040000,
    TF_RXWIN0SENT = 0x00080000, TF_FASTRECOVERY = 0x00100000,
    TF_WASFRECOVERY = 0x00200000, TF_SIGNATURE = 0x00400000,
    TF_FORCEDATA = 0x00800000, TF_TSO = 0x01000000, TF_TOE = 0x02000000,
    TF_CLOSED = 0x04000000, TF_SENTSYN = 0x08000000, TF_LRD = 0x10000000,
    TF_CONGRECOVERY = 0x20000000, TF_WASCRECOVERY = 0x40000000,
    TF_FASTOPEN = 0x80000000,
};

/* Flags for the extended TCP flags field, tp->t_flags2 */
enum {
    TF2_PLPMTU_BLACKHOLE = 0x00000001, TF2_PLPMTU_PMTUD = 0x00000002,
    TF2_PLPMTU_MAXSEGSNT = 0x00000004, TF2_LOG_AUTO = 0x00000008,
    TF2_DROP_AF_DATA = 0x00000010, TF2_ECN_PERMIT = 0x00000020,
    TF2_ECN_SND_CWR = 0x00000040, TF2_ECN_SND_ECE = 0x00000080,
    TF2_ACE_PERMIT = 0x00000100, TF2_HPTS_CPU_SET = 0x00000200,
    TF2_FBYTES_COMPLETE = 0x00000400, TF2_ECN_USE_ECT1 = 0x00000800,
    TF2_TCP_ACCOUNTING = 0x00001000, TF2_HPTS_CALLS = 0x00002000,
    TF2_MBUF_L_ACKS = 0x00004000, TF2_MBUF_ACKCMP = 0x00008000,
    TF2_SUPPORTS_MBUFQ = 0x00010000, TF2_MBUF_QUEUE_READY = 0x00020000,
    TF2_DONT_SACK_QUEUE = 0x00040000, TF2_CANNOT_DO_ECN = 0x00080000,
    TF2_PROC_SACK_PROHIBIT = 0x00100000, TF2_IPSEC_TSO = 0x00200000,
    TF2_NO_ISS_CHECK = 0x00400000,
};

extern bool verbose;
void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid);

/* There are 32 flag values for t_flags. So assume the caller has provided a
 * large enough array to hold 32 x sizeof("TF_CONGRECOVERY |") == 544 bytes.
 */
void
translate_tflags(uint32_t t_flags, char str_array[], uint32_t arr_size)
{
    assert(arr_size >= (32 * sizeof("TF_CONGRECOVERY")));

    if (t_flags & TF_ACKNOW) {
        strcat(str_array, "TF_ACKNOW | ");
    }
    if (t_flags & TF_DELACK) {
        strcat(str_array, "TF_DELACK | ");
    }
    if (t_flags & TF_NODELAY) {
        strcat(str_array, "TF_NODELAY | ");
    }
    if (t_flags & TF_NOOPT) {
        strcat(str_array, "TF_NOOPT | ");
    }
    if (t_flags & TF_SENTFIN) {
        strcat(str_array, "TF_SENTFIN | ");
    }
    if (t_flags & TF_REQ_SCALE) {
        strcat(str_array, "TF_REQ_SCALE | ");
    }
    if (t_flags & TF_RCVD_SCALE) {
        strcat(str_array, "TF_RCVD_SCALE | ");
    }
    if (t_flags & TF_REQ_TSTMP) {
        strcat(str_array, "TF_REQ_TSTMP | ");
    }
    if (t_flags & TF_RCVD_TSTMP) {
        strcat(str_array, "TF_RCVD_TSTMP | ");
    }
    if (t_flags & TF_SACK_PERMIT) {
        strcat(str_array, "TF_SACK_PERMIT | ");
    }
    if (t_flags & TF_NEEDSYN) {
        strcat(str_array, "TF_NEEDSYN | ");
    }
    if (t_flags & TF_NEEDFIN) {
        strcat(str_array, "TF_NEEDFIN | ");
    }
    if (t_flags & TF_NOPUSH) {
        strcat(str_array, "TF_NOPUSH | ");
    }
    if (t_flags & TF_PREVVALID) {
        strcat(str_array, "TF_PREVVALID | ");
    }
    if (t_flags & TF_WAKESOR) {
        strcat(str_array, "TF_WAKESOR | ");
    }
    if (t_flags & TF_GPUTINPROG) {
        strcat(str_array, "TF_GPUTINPROG | ");
    }
    if (t_flags & TF_MORETOCOME) {
        strcat(str_array, "TF_MORETOCOME | ");
    }
    if (t_flags & TF_SONOTCONN) {
        strcat(str_array, "TF_SONOTCONN | ");
    }
    if (t_flags & TF_LASTIDLE) {
        strcat(str_array, "TF_LASTIDLE | ");
    }
    if (t_flags & TF_RXWIN0SENT) {
        strcat(str_array, "TF_RXWIN0SENT | ");
    }
    if (t_flags & TF_FASTRECOVERY) {
        strcat(str_array, "TF_FASTRECOVERY | ");
    }
    if (t_flags & TF_WASFRECOVERY) {
        strcat(str_array, "TF_WASFRECOVERY | ");
    }
    if (t_flags & TF_SIGNATURE) {
        strcat(str_array, "TF_SIGNATURE | ");
    }
    if (t_flags & TF_FORCEDATA) {
        strcat(str_array, "TF_FORCEDATA | ");
    }
    if (t_flags & TF_TSO) {
        strcat(str_array, "TF_TSO | ");
    }
    if (t_flags & TF_TOE) {
        strcat(str_array, "TF_TOE | ");
    }
    if (t_flags & TF_CLOSED) {
        strcat(str_array, "TF_CLOSED | ");
    }
    if (t_flags & TF_SENTSYN) {
        strcat(str_array, "TF_SENTSYN | ");
    }
    if (t_flags & TF_LRD) {
        strcat(str_array, "TF_LRD | ");
    }
    if (t_flags & TF_CONGRECOVERY) {
        strcat(str_array, "TF_CONGRECOVERY | ");
    }
    if (t_flags & TF_WASCRECOVERY) {
        strcat(str_array, "TF_WASCRECOVERY | ");
    }
    if (t_flags & TF_FASTOPEN) {
        strcat(str_array, "TF_FASTOPEN | ");
    }
}

/* There are totally 23 values for t_flags2. So assume the caller has provided a
 * large enough array to hold 23 x sizeof("TF2_PROC_SACK_PROHIBIT |") == 552
 * bytes.
 */
void
translate_tflags2(uint32_t t_flags2, char str_array[], uint32_t arr_size)
{
    assert(arr_size >= (23 * sizeof("TF2_PROC_SACK_PROHIBIT")));

    if (t_flags2 & TF2_PLPMTU_BLACKHOLE) {
        strcat(str_array, "TF2_PLPMTU_BLACKHOLE | ");
    }
    if (t_flags2 & TF2_PLPMTU_PMTUD) {
        strcat(str_array, "TF2_PLPMTU_PMTUD | ");
    }
    if (t_flags2 & TF2_PLPMTU_MAXSEGSNT) {
        strcat(str_array, "TF2_PLPMTU_MAXSEGSNT | ");
    }
    if (t_flags2 & TF2_LOG_AUTO) {
        strcat(str_array, "TF2_LOG_AUTO | ");
    }
    if (t_flags2 & TF2_DROP_AF_DATA) {
        strcat(str_array, "TF2_DROP_AF_DATA | ");
    }
    if (t_flags2 & TF2_ECN_PERMIT) {
        strcat(str_array, "TF2_ECN_PERMIT | ");
    }
    if (t_flags2 & TF2_ECN_SND_CWR) {
        strcat(str_array, "TF2_ECN_SND_CWR | ");
    }
    if (t_flags2 & TF2_ECN_SND_ECE) {
        strcat(str_array, "TF2_ECN_SND_ECE | ");
    }
    if (t_flags2 & TF2_ACE_PERMIT) {
        strcat(str_array, "TF2_ACE_PERMIT | ");
    }
    if (t_flags2 & TF2_HPTS_CPU_SET) {
        strcat(str_array, "TF2_HPTS_CPU_SET | ");
    }
    if (t_flags2 & TF2_FBYTES_COMPLETE) {
        strcat(str_array, "TF2_FBYTES_COMPLETE | ");
    }
    if (t_flags2 & TF2_ECN_USE_ECT1) {
        strcat(str_array, "TF2_ECN_USE_ECT1 | ");
    }
    if (t_flags2 & TF2_TCP_ACCOUNTING) {
        strcat(str_array, "TF2_TCP_ACCOUNTING | ");
    }
    if (t_flags2 & TF2_HPTS_CALLS) {
        strcat(str_array, "TF2_HPTS_CALLS | ");
    }
    if (t_flags2 & TF2_MBUF_L_ACKS) {
        strcat(str_array, "TF2_MBUF_L_ACKS | ");
    }
    if (t_flags2 & TF2_MBUF_ACKCMP) {
        strcat(str_array, "TF2_MBUF_ACKCMP | ");
    }
    if (t_flags2 & TF2_SUPPORTS_MBUFQ) {
        strcat(str_array, "TF2_SUPPORTS_MBUFQ | ");
    }
    if (t_flags2 & TF2_MBUF_QUEUE_READY) {
        strcat(str_array, "TF2_MBUF_QUEUE_READY | ");
    }
    if (t_flags2 & TF2_DONT_SACK_QUEUE) {
        strcat(str_array, "TF2_DONT_SACK_QUEUE | ");
    }
    if (t_flags2 & TF2_CANNOT_DO_ECN) {
        strcat(str_array, "TF2_CANNOT_DO_ECN | ");
    }
    if (t_flags2 & TF2_PROC_SACK_PROHIBIT) {
        strcat(str_array, "TF2_PROC_SACK_PROHIBIT | ");
    }
    if (t_flags2 & TF2_IPSEC_TSO) {
        strcat(str_array, "TF2_IPSEC_TSO | ");
    }
    if (t_flags2 & TF2_NO_ISS_CHECK) {
        strcat(str_array, "TF2_NO_ISS_CHECK | ");
    }
}

void
print_cwd(void)
{
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        PERROR_FUNCTION("getcwd() error");
    } else {
        printf("Current working directory:\n %s\n", cwd);
    }
}

long int
my_atol(const char *str)
{
    char *endptr;
    long int number;
    errno = 0;  // To distinguish success/failure after the call
    number = strtol(str, &endptr, 10);

    // Check for conversion errors
    if (errno == ERANGE) {
        PERROR_FUNCTION("The number is out of range for a long integer.");
    } else if (str == endptr) {
        PERROR_FUNCTION("No digits were found in the string.");
    } else if (*endptr != '\0') {
        printf("Converted number: %ld\n", number);
        printf("Remaining string after number: \"%s\"\n", endptr);
        PERROR_FUNCTION("Partial digits from the string");
    }

    return number;
}

void
fill_flow_info(struct flow_info *target_flow, char *fields[])
{
    if (target_flow != NULL) {
        strcpy(target_flow->laddr, fields[LOIP]);
        target_flow->lport = (uint16_t)my_atol(fields[LPORT]);
        strcpy(target_flow->faddr, fields[FOIP]);
        target_flow->fport = (uint16_t)my_atol(fields[FPORT]);
        target_flow->is_info_set = true;
    }
}

void
timeval_subtract(struct timeval *result, const struct timeval *t1,
                 const struct timeval *t2)
{
    result->tv_sec = t1->tv_sec - t2->tv_sec;
    result->tv_usec = t1->tv_usec - t2->tv_usec;

    // Handle underflow in microseconds
    if (result->tv_usec < 0) {
        result->tv_sec -= 1;
        result->tv_usec += 1000000;
    }
}

inline bool
is_timeval_set(const struct timeval *val)
{
    return (val->tv_sec != 0 || val->tv_usec != 0);
}

char*
next_sub_str_from(char *str, const char *restrict delimiter)
{
    char *str1 = NULL;
    char *str2 = NULL;

    str1 = strtok(str, delimiter);
    str2 = strtok(NULL, delimiter);

    if (str1 == NULL || str2 == NULL) {
        PERROR_FUNCTION("Invalid input string.");
    }

    return str2;
}

/* Function to read the last line of a file */
int
read_last_line(FILE *file, char *lastLine)
{
    long fileSize;
    int pos;

    if (lastLine == NULL) {
        PERROR_FUNCTION("empty buffer");
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);

    for (pos = 1; pos < fileSize; pos++) {
        fseek(file, -pos, SEEK_END);
        if (fgetc(file) == '\n') {
            if (fgets(lastLine, MAX_LINE_LENGTH, file) != NULL) {
                return EXIT_SUCCESS;
            }
        }
    }
    /* If file has only one line, handle that case */
    fseek(file, 0, SEEK_SET);
    if (fgets(lastLine, MAX_LINE_LENGTH, file) != NULL) {
        return EXIT_SUCCESS;
    } else {
        PERROR_FUNCTION("fgets");
        return EXIT_FAILURE;
    }
}

void
fill_fields_from_line(char **fields, char *line)
{
    int field_cnt = 0;

    // Strip newline characters at the end
    line[strcspn(line, "\r\n")] = '\0';

    // Tokenize the line using comma as the delimiter
    char *token = strtok(line, COMMA_DELIMITER);
    while (token != NULL) {
        fields[field_cnt++] = token;
        token = strtok(NULL, COMMA_DELIMITER);
    }
    if (field_cnt != TOTAL_FIELDS){
        printf("\nfield_cnt:%d != TOTAL_FIELDS:%d\n", field_cnt, TOTAL_FIELDS);
        PERROR_FUNCTION("field_cnt != TOTAL_FIELDS");
    }
}

bool
is_flowid_in_file(const struct file_basic_stats *f_basics, uint32_t flowid, int *idx)
{
    for (uint32_t i = 0; i < f_basics->flow_count; i++) {
        if (f_basics->flow_list[i].flowid == flowid) {
            *idx = i;
            return true;
        }
    }
    return false;
}

static inline void
get_first_line_stats(struct file_basic_stats *f_basics)
{
    FILE *file = f_basics->file;
    struct first_line_fields *f_line_stats = NULL;
    char *firstLine = (char *)calloc(MAX_LINE_LENGTH, sizeof(char));
    if (firstLine == NULL) {
        PERROR_FUNCTION("malloc");
        return;
    }

    /* read the last line of a file */
    if (fgets(firstLine, MAX_LINE_LENGTH, file) != NULL) {
        /* 6 fields in the first line */
        char *fields[TOTAL_FIRST_LINE_FIELDS];
        uint32_t field_count = 0;
        f_line_stats = (struct first_line_fields *)malloc(sizeof(*f_line_stats));

        /* Strip newline characters at the end */
        firstLine[strcspn(firstLine, "\r\n")] = '\0';

        /* Tokenize the line using comma as the delimiter */
        char *token = strtok(firstLine, TAB_DELIMITER);
        while (token != NULL) {
            fields[field_count++] = token;
            token = strtok(NULL, TAB_DELIMITER);
        }

        f_line_stats->enable_time.tv_sec = GET_VALUE(fields[ENABLE_TIME_SECS]);
        f_line_stats->enable_time.tv_usec = GET_VALUE(fields[ENABLE_TIME_USECS]);
        strcpy(f_line_stats->siftrver, next_sub_str_from(fields[SIFTRVER],
                                                            EQUAL_DELIMITER));
        strcpy(f_line_stats->sysname, next_sub_str_from(fields[SYSNAME],
                                                           EQUAL_DELIMITER));
        strcpy(f_line_stats->sysver, next_sub_str_from(fields[SYSVER],
                                                          EQUAL_DELIMITER));
        strcpy(f_line_stats->ipmode, next_sub_str_from(fields[IPMODE],
                                                          EQUAL_DELIMITER));

        free(firstLine);
    } else {
        free(firstLine);
        PERROR_FUNCTION("Failed to read the first line.");
        return;
    }

    if (verbose) {
        printf("enable_time: %ld.%ld, siftrver: %s, sysname: %s, sysver: %s, "
                "ipmode: %s\n\n",
                (long)f_line_stats->enable_time.tv_sec,
                (long)f_line_stats->enable_time.tv_usec,
                f_line_stats->siftrver,
                f_line_stats->sysname,
                f_line_stats->sysver,
                f_line_stats->ipmode);
    }

    f_basics->first_line_stats = f_line_stats;
}

static inline void
get_last_line_stats(struct file_basic_stats *f_basics)
{
    FILE *file = f_basics->file;
    struct last_line_fields *l_line_stats = NULL;
    char *lastLine = (char *)calloc(MAX_LINE_LENGTH, sizeof(char));
    if (lastLine == NULL) {
        PERROR_FUNCTION("malloc");
        return;
    }

    if (read_last_line(file, lastLine) == EXIT_SUCCESS) {
        char *fields[TOTAL_LAST_LINE_FIELDS];
        uint32_t field_count = 0;
        l_line_stats = (struct last_line_fields *)malloc(sizeof(*l_line_stats));
        if (l_line_stats == NULL) {
            PERROR_FUNCTION("malloc failed for l_line_stats");
        }

        /* Strip newline characters at the end */
        lastLine[strcspn(lastLine, "\r\n")] = '\0';

        // Tokenize the line using tab as the delimiter
        char *token = strtok(lastLine, TAB_DELIMITER);
        while (token != NULL) {
            fields[field_count++] = token;
            token = strtok(NULL, TAB_DELIMITER);
        }

        if (field_count != TOTAL_LAST_LINE_FIELDS) {
            PERROR_FUNCTION("field_count != TOTAL_LAST_LINE_FIELDS");
        }

        l_line_stats->disable_time.tv_sec = GET_VALUE(fields[DISABLE_TIME_SECS]);
        l_line_stats->disable_time.tv_usec = GET_VALUE(fields[DISABLE_TIME_USECS]);
        l_line_stats->num_inbound_tcp_pkts = GET_VALUE(fields[NUM_INBOUND_TCP_PKTS]);
        l_line_stats->num_outbound_tcp_pkts = GET_VALUE(fields[NUM_OUTBOUND_TCP_PKTS]);
        l_line_stats->total_tcp_pkts = GET_VALUE(fields[TOTAL_TCP_PKTS]);

        l_line_stats->num_inbound_skipped_pkts_malloc = GET_VALUE(fields[NUM_INBOUND_SKIPPED_PKTS_MALLOC]);
        l_line_stats->num_outbound_skipped_pkts_malloc = GET_VALUE(fields[NUM_OUTBOUND_SKIPPED_PKTS_MALLOC]);
        l_line_stats->num_inbound_skipped_pkts_tcpcb = GET_VALUE(fields[NUM_INBOUND_SKIPPED_PKTS_TCPCB]);
        l_line_stats->num_outbound_skipped_pkts_tcpcb = GET_VALUE(fields[NUM_OUTBOUND_SKIPPED_PKTS_TCPCB]);
        l_line_stats->num_inbound_skipped_pkts_inpcb = GET_VALUE(fields[NUM_INBOUND_SKIPPED_PKTS_INPCB]);
        l_line_stats->num_outbound_skipped_pkts_inpcb = GET_VALUE(fields[NUM_OUTBOUND_SKIPPED_PKTS_INPCB]);
        l_line_stats->total_skipped_tcp_pkts = GET_VALUE(fields[TOTAL_SKIPPED_TCP_PKTS]);

        char *sub_str = next_sub_str_from(fields[FLOWID_LIST], EQUAL_DELIMITER);

        l_line_stats->flowid_list = (char*)calloc(strlen(sub_str) + 1, sizeof(char));
        if (l_line_stats->flowid_list == NULL) {
            PERROR_FUNCTION("Failed to calloc the last line.");
        }
        strcpy(l_line_stats->flowid_list, sub_str);

        free(lastLine);
    } else {
        free(lastLine);
        PERROR_FUNCTION("Failed to read the last line.");
        return;
    }

    if (verbose) {
        printf("disable_time: %ld.%ld, num_inbound_tcp_pkts: %" PRIu64
               ", num_outbound_tcp_pkts: %" PRIu64 ", total_tcp_pkts: %" PRIu64
               ", num_inbound_skipped_pkts_malloc: %u, "
               "num_outbound_skipped_pkts_malloc: %u, "
               "num_inbound_skipped_pkts_tcpcb: %u, "
               "num_outbound_skipped_pkts_tcpcb: %u, "
               "num_inbound_skipped_pkts_inpcb: %u, "
               "num_outbound_skipped_pkts_inpcb: %u, "
               "total_skipped_tcp_pkts: %u, "
               "flowid_list: %s\n\n",
               (long)l_line_stats->disable_time.tv_sec,
               (long)l_line_stats->disable_time.tv_usec,
               l_line_stats->num_inbound_tcp_pkts,
               l_line_stats->num_outbound_tcp_pkts,
               l_line_stats->total_tcp_pkts,
               l_line_stats->num_inbound_skipped_pkts_malloc,
               l_line_stats->num_outbound_skipped_pkts_malloc,
               l_line_stats->num_inbound_skipped_pkts_tcpcb,
               l_line_stats->num_outbound_skipped_pkts_tcpcb,
               l_line_stats->num_inbound_skipped_pkts_inpcb,
               l_line_stats->num_outbound_skipped_pkts_inpcb,
               l_line_stats->total_skipped_tcp_pkts,
               l_line_stats->flowid_list);
    }

    f_basics->last_line_stats = l_line_stats;
}

static inline void
get_flow_count(struct file_basic_stats *f_basics)
{
    uint32_t flow_cnt = 0;

    char *flow_list_str = strdup(f_basics->last_line_stats->flowid_list);
    if (flow_list_str == NULL) {
        PERROR_FUNCTION("strdup() failed for flow_list_str");
        return;
    }

    /* get the total number of flows */
    char *token = strtok(flow_list_str, COMMA_DELIMITER);
    while (token != NULL) {
        token = strtok(NULL, COMMA_DELIMITER);
        flow_cnt++;
    }
    f_basics->flow_count = flow_cnt;

    free(flow_list_str);
}

/* get some basic info from the traffic records, exclude head or foot note */
static inline void
get_body_stats(struct file_basic_stats *f_basics) {
    uint32_t lineCount = 0;
    char current_line[MAX_LINE_LENGTH];
    char previous_line[MAX_LINE_LENGTH] = {0};
    FILE *file = f_basics->file;

    if (f_basics->flow_count > 0) {
        f_basics->flow_list = (struct flow_info*)calloc(f_basics->flow_count,
                                                   sizeof(struct flow_info));
    } else {
        printf("%s%u: has not set f_basics->flow_count:%u\n",
               __FUNCTION__, __LINE__, f_basics->flow_count);
        PERROR_FUNCTION("f_basics->flow_count not set");
        return;
    }

    /* Restart seeking and go back to the beginning of the file */
    fseek(file, 0, SEEK_SET);

    // Read and discard the first line
    if(fgets(current_line, MAX_LINE_LENGTH, file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return;
    }
    lineCount++;

    /* Read through the rest of the file line by line */
    while (fgets(current_line, MAX_LINE_LENGTH, file) != NULL) {
        if (previous_line[0] != '\0') {
            char *fields[TOTAL_FIELDS];
            uint32_t flowid;
            int idx;

            fill_fields_from_line(fields, previous_line);
            flowid = my_atol(fields[FLOW_ID]);

            if (!is_flowid_in_file(f_basics, flowid, &idx)) {
                struct flow_info target_flow = { .flowid = flowid };

                for (uint32_t i = 0; i < f_basics->flow_count; i++) {
                    if (f_basics->flow_list[i].flowid == 0) {
                        fill_flow_info(&target_flow, fields);
                        target_flow.record_cnt = 1;
                        if (strcmp(f_basics->first_line_stats->ipmode, "4") == 0) {
                            target_flow.ipver = INP_IPV4;
                        } else {
                            target_flow.ipver = INP_IPV6;
                        }
                        f_basics->flow_list[i] = target_flow;
                        break;
                    }
                }
            } else {
                f_basics->flow_list[idx].record_cnt++;
            }
        }

        lineCount++;
        /* Update the previous line to be the current line. */
        strcpy(previous_line, current_line);
    }

    if (verbose) {
        printf("input file has total lines: %u\n", lineCount);
    }

    f_basics->num_lines = lineCount;
}

int
get_file_basics(struct file_basic_stats *f_basics, const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    if (!file) {
        PERROR_FUNCTION("Failed to open file");
        return EXIT_FAILURE;
    }
    f_basics->file = file;

    get_first_line_stats(f_basics);
    if (f_basics->first_line_stats == NULL) {
        PERROR_FUNCTION("head note not exist");
        return EXIT_FAILURE;
    }

    get_last_line_stats(f_basics);
    if (f_basics->last_line_stats == NULL) {
        PERROR_FUNCTION("foot note not exist");
        return EXIT_FAILURE;
    }

    get_flow_count(f_basics);
    /* f_basics->flow_count must be set first */
    get_body_stats(f_basics);

    return EXIT_SUCCESS;
}

void
show_file_basic_stats(const struct file_basic_stats *f_basics)
{
    struct timeval result;
    double time_in_seconds;

    timeval_subtract(&result, &f_basics->last_line_stats->disable_time,
                     &f_basics->first_line_stats->enable_time);

    time_in_seconds = result.tv_sec + result.tv_usec / 1000000.0;

    printf("siftr version: %s\n", f_basics->first_line_stats->siftrver);

    if (verbose) {
        printf("flow list: %s\n", f_basics->last_line_stats->flowid_list);
    }

    printf("flow id list:\n");
    for (uint32_t i = 0; i < f_basics->flow_count; i++) {
        printf(" flowid:%10u (%s:%hu<->%s:%hu) records:%u\n",
                f_basics->flow_list[i].flowid,
                f_basics->flow_list[i].laddr, f_basics->flow_list[i].lport,
                f_basics->flow_list[i].faddr, f_basics->flow_list[i].fport,
                f_basics->flow_list[i].record_cnt);
    }
    printf("\n");

    printf("starting_time: %jd.%06ld\n",
           f_basics->first_line_stats->enable_time.tv_sec,
           (intmax_t)f_basics->first_line_stats->enable_time.tv_usec);

    printf("ending_time: %jd.%06ld\n",
           f_basics->last_line_stats->disable_time.tv_sec,
           (intmax_t)f_basics->last_line_stats->disable_time.tv_usec);

    printf("log duration: %.2f seconds\n", time_in_seconds);
}

/* Read the body of the per-flow stats, and skip the head or foot note. */
void
read_body_by_flowid(struct file_basic_stats *f_basics, uint32_t flowid)
{
    int idx;

    if (is_flowid_in_file(f_basics, flowid, &idx)) {
        printf("++++++++++++++++++++++++++++++    ++++++++++++++++++++++++++++++\n");
        printf("  %s:%hu->%s:%hu flowid: %u\n",
               f_basics->flow_list[idx].laddr, f_basics->flow_list[idx].lport,
               f_basics->flow_list[idx].faddr, f_basics->flow_list[idx].fport,
               flowid);
        printf("    has %u useful records\n", f_basics->flow_list[idx].record_cnt);

        stats_into_plot_file(f_basics, flowid);
    }
}

int
cleanup_file_basic_stats(const struct file_basic_stats *f_basics_ptr)
{

    // Close the file and check for errors
    if (fclose(f_basics_ptr->file) == EOF) {
        PERROR_FUNCTION("Failed to close file");
        return EXIT_FAILURE;
    }

    free(f_basics_ptr->first_line_stats);
    free(f_basics_ptr->last_line_stats->flowid_list);
    free(f_basics_ptr->last_line_stats);
    free(f_basics_ptr->flow_list);

    return EXIT_SUCCESS;
}

#endif /* REVIEW_SIFTR_LOG_H_ */
