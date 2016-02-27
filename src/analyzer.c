#include "pool.h"

void main()
{
    analyze("/home/trace/UMNtrace1_14.csv","../config/config1.txt","../output/output.txt","../log/log.txt");
}

int analyze(char *trace,char *config,char *output,char *log)
{
	unsigned int i,chunk_num;
	unsigned int size_in_window=0,req_in_window=0,chk_in_window=0;
	long double time_in_window=0;
	double i_non_access=0,i_inactive=0,i_seq_intensive=0,i_seq_less_intensive=0,i_random_intensive=0,i_random_less_intensive=0;

	struct pool_info *pool;
	pool=(struct pool_info *)malloc(sizeof(struct pool_info));
	alloc_assert(pool,"pool");
	memset(pool,0,sizeof(struct pool_info));

	load_parameters(pool,config);
	initialize(pool,trace,output,log);

#ifdef _NETAPP_TRACE_
	chunk_num=get_range_netapp(pool);
	fgets(pool->buffer,SIZE_BUFFER,pool->file_trace);	//read the first line out
	while(get_request_netapp(pool)!=FAILURE)
#else
	chunk_num=get_range_msr(pool);
	while(get_request_msr(pool)!=FAILURE)
#endif
	{
		if(pool->window_type==WINDOW_DATA)
		{
			seq_detection(pool);	//Sequential IO Detection
			update_statistics(pool);

			//update window info
			size_in_window+=pool->req->size;
			req_in_window++;
			if(req_in_window==1)
				pool->window_time_start=pool->req->time;
			pool->window_time_end=pool->req->time;
			
			//THE CURRENT WINDOW IS FULL
			if((size_in_window>=pool->window_size*2048)||(feof(pool->file_trace)!=0)&&(size_in_window>0))
			{
				flush_stream(pool);	//Flush information in POOL->STREAMS into each Chunks
				/*Pattern Detection*/
				time_in_window=(long double)(pool->window_time_end-pool->window_time_start)/(long double)1000000000;
				pool->window_time[pool->window_sum]=time_in_window;
				pool->chunk_access[pool->window_sum]=pool->chunk_win;

				for(i=pool->chunk_min;i<=pool->chunk_max;i++)
				{
					if(pool->chunk[i].req_sum_all==0)//no access
					{
						/*No Access*/
						if(pool->record_all[i].accessed!=0)
						{
							i_non_access++;
						}
						pool->chunk[i].pattern=PATTERN_NON_ACCESS;
					}
					else if(pool->chunk[i].req_sum_all<pool->threshold_inactive)//inactive
					{
						/*Inactive*/
						i_inactive++;
						if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Inactive Read*/
							pool->chunk[i].pattern=PATTERN_INACTIVE_R;
						}
						else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Inactive Write*/
							pool->chunk[i].pattern=PATTERN_INACTIVE_W;
						}
						else{
							/*Inactive Hybrid*/
							pool->chunk[i].pattern=PATTERN_INACTIVE_H;
						}
					}
					else if((pool->chunk[i].seq_size_all/pool->chunk[i].req_size_all)>=pool->threshold_cbr &&
						((long double)pool->chunk[i].seq_sum_all/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_car)
					{
						/*SEQUENTIAL*/
						i_seq_intensive++;
						/*Sequential Intensive*/
						if(pool->chunk[i].req_sum_all>=(req_in_window/pool->chunk_win)*pool->threshold_intensive)
						{
							if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Intensive Read*/
								pool->chunk[i].pattern=PATTERN_SEQ_INTENSIVE_R;
							}
							else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Intensive Write*/
								pool->chunk[i].pattern=PATTERN_SEQ_INTENSIVE_W;
							}
							else
							{
								/*Sequential Intensive Hybrid*/
								pool->chunk[i].pattern=PATTERN_SEQ_INTENSIVE_H;
							}
						}
						else{
							i_seq_less_intensive++;
							if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Less Intensive Read*/
								pool->chunk[i].pattern=PATTERN_SEQ_LESS_INTENSIVE_R;
							}
							else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Less Intensive Write*/
								pool->chunk[i].pattern=PATTERN_SEQ_LESS_INTENSIVE_W;
							}
							else
							{
								/*Sequential Less Intensive Hybrid*/
								pool->chunk[i].pattern=PATTERN_SEQ_LESS_INTENSIVE_H;
							}
						}
					}
					else{
						/*Random*/
						i_random_intensive++;
						if(pool->chunk[i].req_sum_all>=(req_in_window/pool->chunk_win)*pool->threshold_intensive)
						{
							if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Random Intensive Read*/
								pool->chunk[i].pattern=PATTERN_RANDOM_INTENSIVE_R;
							}
							else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Random Intensive Write*/
								pool->chunk[i].pattern=PATTERN_RANDOM_INTENSIVE_W;
							}
							else
							{
								/*Random Intensive Hybrid*/
								pool->chunk[i].pattern=PATTERN_RANDOM_INTENSIVE_H;
							}
						}
						else{
							i_random_less_intensive++;
							if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Random Less Intensive Read*/
								pool->chunk[i].pattern=PATTERN_RANDOM_LESS_INTENSIVE_R;
							}
							else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Random Less Intensive Write*/
								pool->chunk[i].pattern=PATTERN_RANDOM_LESS_INTENSIVE_W;
							}
							else
							{
								/*Random Less Intensive Hybrid*/
								pool->chunk[i].pattern=PATTERN_RANDOM_LESS_INTENSIVE_H;
							}
						}
					}
					//Only record limited information (the first SIZE_ARRY windows)
					if(pool->window_sum<SIZE_ARRAY)
					{
						pool->chunk[i].history_pattern[pool->window_sum]=pool->chunk[i].pattern;

						pool->pattern_non_access[pool->window_sum]=i_non_access/(double)pool->chunk_all;
						pool->pattern_inactive[pool->window_sum]=i_inactive/(double)pool->chunk_all;
						pool->pattern_seq_intensive[pool->window_sum]=i_seq_intensive/(double)pool->chunk_all;
						pool->pattern_seq_less_intensive[pool->window_sum]=i_seq_less_intensive/(double)pool->chunk_all;
						pool->pattern_random_intensive[pool->window_sum]=i_random_intensive/(double)pool->chunk_all;
						pool->pattern_random_less_intensive[pool->window_sum]=i_random_less_intensive/(double)pool->chunk_all;
					}
					
					print_log(pool,i);	//print info of each chunk in this window to log file.
					/*Initialize the statistics in each chunk*/
					pool->chunk[i].req_sum_all=0;
					pool->chunk[i].req_sum_read=0;
					pool->chunk[i].req_sum_write=0;
					pool->chunk[i].req_size_all=0;
					pool->chunk[i].req_size_read=0;
					pool->chunk[i].req_size_write=0;

					pool->chunk[i].seq_sum_all=0;
					pool->chunk[i].seq_sum_read=0;
					pool->chunk[i].seq_sum_write=0;
					pool->chunk[i].seq_stream_all=0;
					pool->chunk[i].seq_stream_read=0;
					pool->chunk[i].seq_stream_write=0;
					pool->chunk[i].seq_size_all=0;
					pool->chunk[i].seq_size_read=0;
					pool->chunk[i].seq_size_write=0;
				}//for
				
				/*Update the pool info*/
				pool->window_sum++;
				if(pool->window_sum%20==0)
					printf("------pool->window_sum=%d---------\n",pool->window_sum);
				pool->window_time_start=0;
				pool->window_time_end=0;
				
				/*Start a new window*/
				size_in_window=0;
				req_in_window=0;
				time_in_window=0;
				
				i_non_access=0;
				i_inactive=0;
				i_seq_intensive=0;
				i_seq_less_intensive=0;
				i_random_intensive=0;
				i_random_less_intensive=0;

				//accessed chunks in each window
				memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_sum);
				printf("pool->chunk_win=%d\n",pool->chunk_win);
				pool->chunk_win=0;
			}//if
		}//if
	}//while

	print_statistics(pool);

	fclose(pool->file_trace);
	fclose(pool->file_output);
	fclose(pool->file_log);
	
	free(pool->chunk);
	free(pool->map);
	free(pool->req);
	free(pool);

	return SUCCESS;
}
