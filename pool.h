#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define _NETAPP_TRACE_

#define SUCCESS		0
#define FAILURE		1
#define READ		0
#define WRITE		1

#define SCM			1
#define SSD			2
#define HDD			3

#define SIZE_BUFFER 200
#define SIZE_ARRAY	250

#define WINDOW_DATA		0		//GB IO SIZE
#define WINDOW_TIME		1		//MINUTES
#define	WINDOW_REQ		2		//K IO REQ.

//  A list of IO patterns. The decision depends on the model (e.g. chunk movement between two pools
//  or among three pools.

#define PATTERN_UNKNOWN				' '		//Intial pattern
#define PATTERN_INTENSIVE_READ		'R'		//Most-intensive-read | decision: SSD, SCM?
#define PATTERN_INTENSIVE_WRITE		'W'		//Most-intensive-write | decision: HOT-->SCM
#define PATTERN_INTENSIVE_HYBRID	'H'		//Hybrid-pattern of high IOPS
#define PATTERN_RANDOM_READ			'r'		//Random-read
#define PATTERN_RANDOM_WRITE		'w'		//Random-write -->SSD
#define PATTERN_RANDOM_HYBRID		'h'
#define PATTERN_INACTIVE			'_'		//Inactive data
#define PATTERN_SEQUENTIAL_READ		'S'		//SEQ
#define PATTERN_SEQUENTIAL_WRITE	's'	
#define PATTERN_SEQUENTIAL_HYBRID	'c'	
#define PATTERN_SEMI_SEQUENTIAL		'Q'

struct pool_info{
	unsigned int size_scm;
	unsigned int size_ssd;
	unsigned int size_hdd;
	unsigned int size_chunk;
	unsigned int size_stream;	//sequential detection
	unsigned int size_stride;
	unsigned int size_interval;
	
	unsigned int chunk_sum;	//total in storage pool
	unsigned int chunk_max;
	unsigned int chunk_min;
	unsigned int chunk_all;	//all accessed
	unsigned int chunk_win;	//in one window

	unsigned int window_type;
	unsigned int window_size;
	unsigned int window_sum;
	long long window_time_start;		// ns
	long long window_time_end;			// ns
	
	double threshold_rw;
	double threshold_cbr;
	double threshold_car;
	unsigned int threshold_size;

	long long time_start;
	long long time_end;

	unsigned int req_sum_all;		// IO num
	unsigned int req_sum_read;
	unsigned int req_sum_write;
	long double req_size_all;		// IO size
	long double req_size_read;
	long double req_size_write;
	
	unsigned int seq_sum_all;		// Seq. IO num
	unsigned int seq_sum_read;
	unsigned int seq_sum_write;
	long double	seq_size_all;		// Seq. IO size
	long double seq_size_read;
	long double seq_size_write;
	
	unsigned int seq_stream_all;	// Seq. stream num
	unsigned int seq_stream_read;
	unsigned int seq_stream_write;

	long double window_time[SIZE_ARRAY];// s
	unsigned int chunk_access[SIZE_ARRAY];
	double pattern_inactive[SIZE_ARRAY];
	double pattern_intensive[SIZE_ARRAY];
	double pattern_sequential[SIZE_ARRAY];
	char buffer[SIZE_BUFFER];

	char filename_trace[100];
	char filename_output[100];
	char filename_config[100];
	FILE *file_trace;
	FILE *file_output;
	FILE *file_config;

	struct chunk_info	*chunk;
	struct request_info *req;
	struct stream_info	*stream;
	struct map_info		*map;
	struct record_info	*record;
};

struct chunk_info{
	char history_pattern[SIZE_ARRAY];
	short history_migration[SIZE_ARRAY];
	
	unsigned int pattern;
	unsigned int location;	//SCM,SSD OR HDD

	/*information in a window*/
	unsigned int req_sum_all;		// IO num
	unsigned int req_sum_read;
	unsigned int req_sum_write;
	long double req_size_all;		// IO size
	long double req_size_read;
	long double req_size_write;
	
	unsigned int seq_sum_all;		// Seq. IO num
	unsigned int seq_sum_read;
	unsigned int seq_sum_write;
	unsigned int seq_stream_all;	// Seq. stream num
	unsigned int seq_stream_read;
	unsigned int seq_stream_write;
	long double	seq_size_all;		// Seq. IO size
	long double seq_size_read;
	long double seq_size_write;
};

struct request_info{
	long long time;
	long long lba;
	unsigned int type;//0->Read,1->Write
	unsigned int size;
};

/*Sequential Accesses Detection*/
struct stream_info{
	unsigned int chk_id;
	unsigned int type;	//read or write
	unsigned int sum;	//IO requests absorbed in
	unsigned int size;	//Sectors(512Bytes)
	long long min;		//start lba
	long long max;		//current max lba
	long long time;		//time when the first req arrived
};

struct map_info{
	unsigned int lcn;	//logical chunk number
	unsigned int pcn;	//physical chunk number
};

struct record_info{
	unsigned int accessed;//accessed or not in a window
};
//initialize.c
void load_parameters(struct pool_info *pool,char *config);
void initialize(struct pool_info *pool,char *trace,char *output);
//pool.c
int get_range_msr(struct pool_info *pool);
int get_range_netapp(struct pool_info *pool);
int get_request_msr(struct pool_info *pool);
int get_request_netapp(struct pool_info *pool);
void update_statistics(struct pool_info *pool);
void print_statistics(struct pool_info *pool);
void alloc_assert(void *p,char *s);
void seq_detection(struct pool_info *pool);
void flush_stream(struct pool_info *pool);

int analyze(char *trace,char *config,char *output);