#include "pool.h"

int get_range_msr(struct pool_info *pool)
{
	int i,j=0;
	long long req_timestamp,req_offset;
	char req_hostname[10],req_type[10];
	unsigned int req_disknumber,req_size,req_responsetime;
	long long lba_max=0,lba_min=0x7fffffffffffffff;
	unsigned int chk_id;

	while(fgets(pool->buffer,SIZE_BUFFER,pool->file_trace))
	{
		for(i=0;i<sizeof(pool->buffer);i++)
		{
			if(pool->buffer[i]==',')
				pool->buffer[i]=' ';
		}
		sscanf(pool->buffer,"%lld %s %d %s %lld %d %d\n",&req_timestamp,req_hostname,
			&req_disknumber,req_type,&req_offset,&req_size,&req_responsetime);
		if((req_timestamp<0)||(req_disknumber<0)||(req_offset<0)||(req_size<0)||(req_responsetime<0))
		{
			printf("get_request_msr()--Error in Trace File!\n");
			printf("%s\n",pool->buffer);
			exit(-1);
		}
		j++;
		if(j%1000000==0)
			printf("scanning(%s)%d\n",pool->filename_trace,j);
		if(j==1)
			pool->time_start=req_timestamp;
		pool->time_end=req_timestamp;

		if(req_offset<lba_min)
			lba_min=req_offset;
		if(req_offset>lba_max)
			lba_max=req_offset;

		chk_id=(unsigned int)((req_offset/512)/(pool->size_chunk*2048));
		if(pool->record_win[chk_id].accessed==0)
		{
			pool->chunk_all++;
			pool->record_win[chk_id].accessed=1;
		}
		if(pool->record_all[chk_id].accessed==0)
		{
			pool->record_all[chk_id].accessed=1;
		}
	}
	pool->chunk_min=(int)((lba_min/512)/(pool->size_chunk*1024*2));
	pool->chunk_max=(int)((lba_max/512)/(pool->size_chunk*1024*2));
	printf("------------Chunks: min=%d, max=%d, total=%d, exactly=%d------------\n",
		pool->chunk_min,pool->chunk_max,pool->chunk_max-pool->chunk_min+1,pool->chunk_all);
	
	memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_sum);
	fclose(pool->file_trace);
	pool->file_trace=fopen(pool->filename_trace,"r");
	
	return pool->chunk_max-pool->chunk_min+1;
}

int get_range_netapp(struct pool_info *pool)
{
	unsigned int i,j=0;
	long double elapsed;
	char cmd[10];
	int lun_ssid,op,phase,nblks,host_id;
	long long lba;
	long long lba_max=0,lba_min=0x7fffffffffffffff;
	unsigned int chk_id;

	fgets(pool->buffer,SIZE_BUFFER,pool->file_trace);	//read the first line out
	while(fgets(pool->buffer,SIZE_BUFFER,pool->file_trace))
	{
		for(i=0;i<sizeof(pool->buffer);i++)
		{
			if(pool->buffer[i]==',')
				pool->buffer[i]=' ';
		}
		sscanf(pool->buffer,"%Lf %s %d %d %d %lld %d %d\n",&elapsed,cmd,
			&lun_ssid,&op,&phase,&lba,&nblks,&host_id);
		if((elapsed<0)||(lun_ssid<0)||(op<0)||(phase<0)||(lba<0)||(nblks<0)||(host_id<0))
		{
			printf("get_range_netapp()--Error in Trace File!\n");
			printf("%s\n",pool->buffer);
			exit(-1);
		}
		j++;
		if(j%1000000==0)
			printf("scanning(%s)%d\n",pool->filename_trace,j);
		if(j==1)
			pool->time_start=(long long)(elapsed*1000);
		pool->time_end=(long long)(elapsed*1000);

		if(lba<lba_min)
			lba_min=lba;
		if(lba>lba_max)
			lba_max=lba;

		chk_id=(int)(lba/(pool->size_chunk*2048));
		if(pool->record_win[chk_id].accessed==0)
		{
			pool->chunk_all++;
			pool->record_win[chk_id].accessed=1;
		}
		if(pool->record_all[chk_id].accessed==0)
		{
			pool->record_all[chk_id].accessed=1;
		}
	}
	pool->chunk_min=(int)(lba_min/(pool->size_chunk*1024*2));
	pool->chunk_max=(int)(lba_max/(pool->size_chunk*1024*2));
	printf("------------Chunks: min=%d, max=%d, total=%d, exactly=%d------------\n",
		pool->chunk_min,pool->chunk_max,pool->chunk_max-pool->chunk_min+1,pool->chunk_all);
	
	memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_sum);
	fclose(pool->file_trace);
	pool->file_trace=fopen(pool->filename_trace,"r");

	return pool->chunk_max-pool->chunk_min+1;
}

int get_request_msr(struct pool_info *pool)
{
	int i;
	long long req_timestamp,req_offset;
	char req_hostname[10],req_type[10];
	unsigned int req_disknumber,req_size,req_responsetime;
	time_t time_current;

	if(feof(pool->file_trace))
	{
		printf("************Read file <%s> end************\n",pool->filename_trace);
		return FAILURE;
	}
	
	fgets(pool->buffer,SIZE_BUFFER,pool->file_trace);
	for(i=0;i<sizeof(pool->buffer);i++)
	{
		if(pool->buffer[i]==',')
			pool->buffer[i]=' ';
	}
	sscanf(pool->buffer,"%lld %s %d %s %lld %d %d\n",&req_timestamp,req_hostname,
			&req_disknumber,req_type,&req_offset,&req_size,&req_responsetime);
	
	
	pool->req->time=req_timestamp;
	pool->req->type=strcmp(req_type,"Read");//strcmp(str1,str2):if(str1==str2)return 0
	if(pool->req->type!=READ)
		pool->req->type=WRITE;
	pool->req->lba=req_offset/512;	//Bytes-->Sectors
	pool->req->size=req_size/512;

	if(pool->req_sum_all%1000000==0)
	{
		time(&time_current);
		printf("Analyzing(%s)%d @%s",pool->filename_trace,pool->req_sum_all,ctime(&time_current));
	}
	return SUCCESS;
} 

int get_request_netapp(struct pool_info *pool)
{
	int i;
	long double elapsed;
	char cmd[10];
	unsigned int lun_ssid,op,phase,nblks,host_id;
	long long lba;
	time_t time_current;

	if(feof(pool->file_trace))
	{
		printf("************Read file <%s> end************\n",pool->filename_trace);
		return FAILURE;
	}

	fgets(pool->buffer,SIZE_BUFFER,pool->file_trace);
	for(i=0;i<sizeof(pool->buffer);i++)
	{
		if(pool->buffer[i]==',')
			pool->buffer[i]=' ';
	}
	sscanf(pool->buffer,"%Lf %s %d %d %d %lld %d %d\n",&elapsed,cmd,
			&lun_ssid,&op,&phase,&lba,&nblks,&host_id);
	
	pool->req->time=(long long)(elapsed*1000);
	pool->req->type=op;
	pool->req->lba=lba;
	pool->req->size=nblks;

	if(pool->req_sum_all%1000000==0)
	{
		time(&time_current);
		printf("Analyzing(%s)%d @%s",pool->filename_trace,pool->req_sum_all,ctime(&time_current));
	}
	return SUCCESS;
} 

void update_statistics(struct pool_info *pool)
{
	unsigned int chk_id=(unsigned int)(pool->req->lba/(pool->size_chunk*2048));
	
	pool->req_sum_all++;
	pool->req_size_all+=(long double)pool->req->size/2048;
	pool->chunk[chk_id].req_sum_all++;
	pool->chunk[chk_id].req_size_all+=(long double)pool->req->size/2048;
	if(pool->req->type==READ)
	{
		pool->req_sum_read++;
		pool->req_size_read+=(long double)pool->req->size/2048;
		pool->chunk[chk_id].req_sum_read++;
		pool->chunk[chk_id].req_size_read+=(long double)pool->req->size/2048;
	}
	else
	{
		pool->req_sum_write++;
		pool->req_size_write+=(long double)pool->req->size/2048;
		pool->chunk[chk_id].req_sum_write++;
		pool->chunk[chk_id].req_size_write+=(long double)pool->req->size/2048;
	}
	if(pool->record_win[chk_id].accessed==0)
		pool->chunk_win++;
	pool->record_win[chk_id].accessed=1;
}

void print_statistics(struct pool_info *pool)
{
	unsigned int i,j;
	fprintf(pool->file_output,"%-30s	%s\n","Trace file",pool->filename_trace);
	fprintf(pool->file_output,"\n------Information of Storage Pool------\n");
	fprintf(pool->file_output,"%-30s	%d\n","Size of SCM (GB)",pool->size_scm);
	fprintf(pool->file_output,"%-30s	%d\n","Size of SSD (GB)",pool->size_ssd);
	fprintf(pool->file_output,"%-30s	%d\n","Size of HDD (GB)",pool->size_hdd);
	fprintf(pool->file_output,"%-30s	%d\n","Size of chunk (MB)",pool->size_chunk);
	fprintf(pool->file_output,"%-30s	%d\n","Size of stream",pool->size_stream);
	fprintf(pool->file_output,"%-30s	%d\n","Size of stride (KB)",pool->size_stride/2);
	fprintf(pool->file_output,"%-30s	%d\n","Size of interval",pool->size_interval);
	fprintf(pool->file_output,"%-30s	%d\n","Chunk sum",pool->chunk_sum);
	fprintf(pool->file_output,"%-30s	%d\n","Chunk max",pool->chunk_max);
	fprintf(pool->file_output,"%-30s	%d\n","Chunk min",pool->chunk_min);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Chunk all",pool->chunk_all,100*(long double)pool->chunk_all/(long double)pool->chunk_sum);
	fprintf(pool->file_output,"%-30s	%d\n","Window type",pool->window_type);
	fprintf(pool->file_output,"%-30s	%d\n","Window size (MB)",pool->window_size);
	fprintf(pool->file_output,"%-30s	%lf\n","Threshold for R/W",pool->threshold_rw);
	fprintf(pool->file_output,"%-30s	%lf\n","Threshold for Seq.CBR(Byte)",pool->threshold_cbr);
	fprintf(pool->file_output,"%-30s	%lf\n","Threshold for Seq.CAR(Access)",pool->threshold_car);
	fprintf(pool->file_output,"%-30s	%d\n","Threshold for Seq.size (KB)",pool->threshold_size/2);
	fprintf(pool->file_output,"%-30s	%d\n","Threshold for Inactive",pool->threshold_inactive);
	fprintf(pool->file_output,"%-30s	%d\n","Threshold for Intensive",pool->threshold_intensive);
	fflush(pool->file_output);
	fprintf(pool->file_output,"\n------Information of IO Trace------\n");
	fprintf(pool->file_output,"%-30s	%Lf\n","Trace start time (s)",(long double)pool->time_start/1000000000);
	fprintf(pool->file_output,"%-30s	%Lf\n","Trace end time (s)",(long double)pool->time_end/1000000000);
	fprintf(pool->file_output,"%-30s	%d\n","Num of windows",pool->window_sum);
	fprintf(pool->file_output,"----IO Request--\n");
	fprintf(pool->file_output,"%-30s	%d\n","Num of all  IO ",pool->req_sum_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of read IO",pool->req_sum_read,100*(long double)pool->req_sum_read/(long double)pool->req_sum_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of wrte IO",pool->req_sum_write,100*(long double)pool->req_sum_write/(long double)pool->req_sum_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Size of all  IO (MB)",pool->req_size_all);
	fprintf(pool->file_output,"%-30s	%-20Lf	(%Lf%%)\n","Size of read IO (MB)",pool->req_size_read,100*pool->req_size_read/pool->req_size_all);
	fprintf(pool->file_output,"%-30s	%-20Lf	(%Lf%%)\n","Size of wrte IO (MB)",pool->req_size_write,100*pool->req_size_write/pool->req_size_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of all  IO (MB)",pool->req_size_all/pool->req_sum_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of read IO (MB)",pool->req_size_read/pool->req_sum_read);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of wrte IO (MB)",pool->req_size_write/pool->req_sum_write);
	fprintf(pool->file_output,"----Sequential IO Request--\n");
	fprintf(pool->file_output,"%-30s	%d\n","Num of Seq. all  IO",pool->seq_sum_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of Seq. read IO",pool->seq_sum_read,100*(long double)pool->seq_sum_read/(long double)pool->seq_sum_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of Seq. wrte IO",pool->seq_sum_write,100*(long double)pool->seq_sum_write/(long double)pool->seq_sum_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Size of Seq. all  IO (MB)",pool->seq_size_all);
	fprintf(pool->file_output,"%-30s	%-20Lf	(%Lf%%)\n","Size of Seq. read IO (MB)",pool->seq_size_read,100*pool->seq_size_read/pool->seq_size_all);
	fprintf(pool->file_output,"%-30s	%-20Lf	(%Lf%%)\n","Size of Seq. wrte IO (MB)",pool->seq_size_write,100*pool->seq_size_write/pool->seq_size_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of Seq. all  IO (MB)",pool->seq_size_all/pool->seq_sum_all);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of Seq. read IO (MB)",pool->seq_size_read/pool->seq_sum_read);
	fprintf(pool->file_output,"%-30s	%Lf\n","Avg Size of Seq. wrte IO (MB)",pool->seq_size_write/pool->seq_sum_write);
	fprintf(pool->file_output,"----Sequential Stream--\n");
	fprintf(pool->file_output,"%-30s	%d\n","Num of Seq. all  stream",pool->seq_stream_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of Seq. read stream",pool->seq_stream_read,100*(long double)pool->seq_stream_read/(long double)pool->seq_stream_all);
	fprintf(pool->file_output,"%-30s	%-20d	(%Lf%%)\n","Num of Seq. wrte stream",pool->seq_stream_write,100*(long double)pool->seq_stream_write/(long double)pool->seq_stream_all);
	fprintf(pool->file_output,"%-30s	%Lf MB\n","Avg Size of Seq. all  stream",pool->seq_size_all/pool->seq_stream_all);
	fprintf(pool->file_output,"%-30s	%Lf MB\n","Avg Size of Seq. read stream",pool->seq_size_read/pool->seq_stream_read);
	fprintf(pool->file_output,"%-30s	%Lf MB\n","Avg Size of Seq. wrte stream",pool->seq_size_write/pool->seq_stream_write);
	fflush(pool->file_output);
	fprintf(pool->file_output,"\n------Information of IO Pattern Ratio------\n");	//IO pattern ratio of each window
	if(pool->window_sum > SIZE_ARRAY)
		pool->window_sum=SIZE_ARRAY;
	fprintf(pool->file_output,"[non_access]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_non_access[j]);
	fprintf(pool->file_output,"\n");
	fprintf(pool->file_output,"[inactive]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_inactive[j]);
	fprintf(pool->file_output,"\n");
	fprintf(pool->file_output,"[seq_intensive]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_seq_intensive[j]);
	fprintf(pool->file_output,"\n");
	fprintf(pool->file_output,"[seq_less_intensive]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_seq_less_intensive[j]);
	fprintf(pool->file_output,"\n");
	fprintf(pool->file_output,"[random_intensive]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_random_intensive[j]);
	fprintf(pool->file_output,"\n");
	fprintf(pool->file_output,"[less_intensive]\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%lf ",pool->pattern_random_less_intensive[j]);
	fprintf(pool->file_output,"\n");
	fflush(pool->file_output);
	fprintf(pool->file_output,"\n------Information of Time in Each Window------\n");
	for(j=0;j<pool->window_sum;j++)
		fprintf(pool->file_output,"%s %-10d	 %-15Lf	%d\n","Time in window",j,pool->window_time[j],pool->chunk_access[j]);
	fflush(pool->file_output);
	fprintf(pool->file_output,"\n------Information of IO Pattern in Each Window------\n");
	fprintf(pool->file_output,"%-10s	%s\n","CHUNK_ID","PATTERN_HISTORY");
	for(i=pool->chunk_min;i<=pool->chunk_max;i++)
	{
		if(pool->record_all[i].accessed!=0)
		{
			fprintf(pool->file_output,"%-10d	",i);
			for(j=0;j<pool->window_sum;j++)
				fprintf(pool->file_output,"%c",pool->chunk[i].history_pattern[j]);
			fprintf(pool->file_output,"\n");
		}
	}
	fflush(pool->file_output);
}

void alloc_assert(void *p,char *s)
{
	if(p!=NULL)
		return;
	printf("malloc %s error\n",s);
	getchar();
	exit(-1);
}

//Sequential IO Detection
void seq_detection(struct pool_info *pool)
{
	unsigned int i,distribute=FAILURE;
	long long min_time=0x7fffffffffffffff;
	unsigned int min_stream; 

	for(i=0;i<pool->size_stream;i++)
	{
		if(pool->stream[i].size!=0)
		{
			if(pool->req->type==pool->stream[i].type)
			{
				if((pool->req->lba>=pool->stream[i].min)&&
					(pool->req->lba<=(pool->stream[i].max+pool->size_stride)))
				{
					pool->stream[i].sum++;
					pool->stream[i].size+=pool->req->size;
					if((pool->req->lba+pool->req->size)>(pool->stream[i].max+pool->size_stride))
					{
						pool->stream[i].max=pool->req->lba+pool->req->size;
					}
					pool->stream[i].time=pool->req->time;
					distribute=SUCCESS;
					break;
				}
			}
		}
	}
	if(distribute!=SUCCESS)
	{
		for(i=0;i<pool->size_stream;i++)
		{
			if(pool->stream[i].size==0)
			{
				pool->stream[i].chk_id=(unsigned int)(pool->req->lba/(pool->size_chunk*2048));
				pool->stream[i].type=pool->req->type;
				pool->stream[i].sum=1;
				pool->stream[i].size=pool->req->size;
				pool->stream[i].min=pool->req->lba;
				pool->stream[i].max=pool->req->lba+pool->req->size-1;
				pool->stream[i].time=pool->req->time;
				distribute=SUCCESS;
				break;
			}
		}
	}
	if(distribute!=SUCCESS)/*Using LRU to kick out a stream*/
	{
		for(i=0;i<pool->size_stream;i++)
		{
			if(pool->stream[i].time<min_time)
			{
				min_time=pool->stream[i].time;
				min_stream=i;
			}
		}
		if(pool->stream[min_stream].size>=pool->threshold_size)
		{
			pool->seq_stream_all++;
			pool->seq_sum_all+=pool->stream[min_stream].sum;
			pool->seq_size_all+=(long double)pool->stream[min_stream].size/2048;
			pool->chunk[pool->stream[min_stream].chk_id].seq_stream_all++;
			pool->chunk[pool->stream[min_stream].chk_id].seq_sum_all+=pool->stream[min_stream].sum;
			pool->chunk[pool->stream[min_stream].chk_id].seq_size_all+=(long double)pool->stream[min_stream].size/2048;
			if(pool->stream[min_stream].type==READ)
			{
				pool->seq_stream_read++;
				pool->seq_sum_read+=pool->stream[min_stream].sum;
				pool->seq_size_read+=(long double)pool->stream[min_stream].size/2048;
				pool->chunk[pool->stream[min_stream].chk_id].seq_stream_read++;
				pool->chunk[pool->stream[min_stream].chk_id].seq_sum_read+=pool->stream[min_stream].sum;
				pool->chunk[pool->stream[min_stream].chk_id].seq_size_read+=(long double)pool->stream[min_stream].size/2048;
			}
			else
			{
				pool->seq_stream_write++;
				pool->seq_sum_write+=pool->stream[min_stream].sum;
				pool->seq_size_write+=(long double)pool->stream[min_stream].size/2048;
				pool->chunk[pool->stream[min_stream].chk_id].seq_stream_write++;
				pool->chunk[pool->stream[min_stream].chk_id].seq_sum_write+=pool->stream[min_stream].sum;
				pool->chunk[pool->stream[min_stream].chk_id].seq_size_write+=(long double)pool->stream[min_stream].size/2048;
			}
		}
		pool->stream[min_stream].chk_id=(unsigned int)(pool->req->lba/(pool->size_chunk*2048));
		pool->stream[min_stream].type=pool->req->type;
		pool->stream[min_stream].sum=1;
		pool->stream[min_stream].size=pool->req->size;
		pool->stream[min_stream].min=pool->req->lba;
		pool->stream[min_stream].max=pool->req->lba+pool->req->size-1;
		pool->stream[min_stream].time=pool->req->time;
	}//if
}

void flush_stream(struct pool_info *pool)
{
	unsigned int i;
	/**Flush information in POOL->STREAMS into each Chunks**/
	for(i=0;i<pool->size_stream;i++)
	{
		if(pool->stream[i].size!=0)
		{
			if(pool->stream[i].size>=pool->threshold_size)
			{
				pool->seq_stream_all++;
				pool->seq_sum_all+=pool->stream[i].sum;
				pool->seq_size_all+=(long double)pool->stream[i].size/2048;
				pool->chunk[pool->stream[i].chk_id].seq_stream_all++;
				pool->chunk[pool->stream[i].chk_id].seq_sum_all+=pool->stream[i].sum;
				pool->chunk[pool->stream[i].chk_id].seq_size_all+=(long double)pool->stream[i].size/2048;
				if(pool->stream[i].type==READ)
				{
					pool->seq_stream_read++;
					pool->seq_sum_read+=pool->stream[i].sum;
					pool->seq_size_read+=(long double)pool->stream[i].size/2048;
					pool->chunk[pool->stream[i].chk_id].seq_stream_read++;
					pool->chunk[pool->stream[i].chk_id].seq_sum_read+=pool->stream[i].sum;
					pool->chunk[pool->stream[i].chk_id].seq_size_read+=(long double)pool->stream[i].size/2048;
				}
				else
				{
					pool->seq_stream_write++;
					pool->seq_sum_write+=pool->stream[i].sum;
					pool->seq_size_write+=(long double)pool->stream[i].size/2048;
					pool->chunk[pool->stream[i].chk_id].seq_stream_write++;
					pool->chunk[pool->stream[i].chk_id].seq_sum_write+=pool->stream[i].sum;
					pool->chunk[pool->stream[i].chk_id].seq_size_write+=(long double)pool->stream[i].size/2048;
				}
			}
		}
		pool->stream[i].chk_id=0;
		pool->stream[i].type=0;
		pool->stream[i].sum=0;
		pool->stream[i].size=0;		
		pool->stream[i].min=0;
		pool->stream[i].max=0;
		pool->stream[i].time=0;
	}
}

void print_log(struct pool_info *pool,unsigned int i)
{
	if(pool->record_all[i].accessed!=0)
	{
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"a",pool->chunk[i].req_sum_all);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"r ",pool->chunk[i].req_sum_read);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"w ",pool->chunk[i].req_sum_write);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"a (MB)",pool->chunk[i].req_size_all);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"r (MB)",pool->chunk[i].req_size_read);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"w (MB)",pool->chunk[i].req_size_write);

		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. a",pool->chunk[i].seq_sum_all);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. r",pool->chunk[i].seq_sum_read);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. w",pool->chunk[i].seq_sum_write);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"Seq. a(MB)",pool->chunk[i].seq_size_all);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"Seq. r(MB)",pool->chunk[i].seq_size_read);
		fprintf(pool->file_log,"[%d][%d] %-10s	%Lf\n",pool->window_sum,i,"Seq. w(MB)",pool->chunk[i].seq_size_write);
	
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. a stream",pool->chunk[i].seq_stream_all);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. r stream",pool->chunk[i].seq_stream_read);
		fprintf(pool->file_log,"[%d][%d] %-10s	%d\n",pool->window_sum,i,"Seq. w stream",pool->chunk[i].seq_stream_write);
		fprintf(pool->file_log,"\n");
		fflush(pool->file_log);

		/*
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of all  IO ",pool->chunk[i].req_sum_all);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of read IO",pool->chunk[i].req_sum_read);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of wrte IO",pool->chunk[i].req_sum_write);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of all  IO (MB)",pool->chunk[i].req_size_all);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of read IO (MB)",pool->chunk[i].req_size_read);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of wrte IO (MB)",pool->chunk[i].req_size_write);

		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. all  IO",pool->chunk[i].seq_sum_all);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. read IO",pool->chunk[i].seq_sum_read);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. wrte IO",pool->chunk[i].seq_sum_write);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of Seq. all  IO (MB)",pool->chunk[i].seq_size_all);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of Seq. read IO (MB)",pool->chunk[i].seq_size_read);
		fprintf(pool->file_log,"[%d][%d] %-30s	%Lf\n",pool->window_sum,i,"Size of Seq. wrte IO (MB)",pool->chunk[i].seq_size_write);
	
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. all  stream",pool->chunk[i].seq_stream_all);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. read stream",pool->chunk[i].seq_stream_read);
		fprintf(pool->file_log,"[%d][%d] %-30s	%d\n",pool->window_sum,i,"Num of Seq. wrte stream",pool->chunk[i].seq_stream_write);
		fprintf(pool->file_log,"\n");
		fflush(pool->file_log);
		*/
	}
}
