#include "pool.h"

int main()
{
	analyze("F:\\Netapp Trace\\trace\\UMNtrace1.csv","F:\\Netapp Trace\\config\\config1.txt","F:\\Netapp Trace\\result\\UMNtrace1_1.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace2.csv","F:\\Netapp Trace\\config\\config1.txt","F:\\Netapp Trace\\result\\UMNtrace2_1.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace3.csv","F:\\Netapp Trace\\config\\config1.txt","F:\\Netapp Trace\\result\\UMNtrace3_1.txt");
	
	analyze("F:\\Netapp Trace\\trace\\UMNtrace1.csv","F:\\Netapp Trace\\config\\config2.txt","F:\\Netapp Trace\\result\\UMNtrace1_2.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace2.csv","F:\\Netapp Trace\\config\\config2.txt","F:\\Netapp Trace\\result\\UMNtrace2_2.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace3.csv","F:\\Netapp Trace\\config\\config2.txt","F:\\Netapp Trace\\result\\UMNtrace3_2.txt");

	analyze("F:\\Netapp Trace\\trace\\UMNtrace1.csv","F:\\Netapp Trace\\config\\config3.txt","F:\\Netapp Trace\\result\\UMNtrace1_3.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace2.csv","F:\\Netapp Trace\\config\\config3.txt","F:\\Netapp Trace\\result\\UMNtrace2_3.txt");
	analyze("F:\\Netapp Trace\\trace\\UMNtrace3.csv","F:\\Netapp Trace\\config\\config3.txt","F:\\Netapp Trace\\result\\UMNtrace3_3.txt");

	return 1;
}

int analyze(char *trace,char *config,char *output)
{
	unsigned int i,chunk_num;
	unsigned int size_in_window=0,req_in_window=0,chk_in_window=0;
	long double time_in_window=0;
	double i_inactive=0,i_sequential=0,i_intensive=0;

	struct pool_info *pool;
	pool=(struct pool_info *)malloc(sizeof(struct pool_info));
	alloc_assert(pool,"pool");
	memset(pool,0,sizeof(struct pool_info));

	load_parameters(pool,config);
	initialize(pool,trace,output);

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
					if(pool->chunk[i].req_sum_all<1)//inactive
					{
						/*INACTIVE*/
						i_inactive++;
						/*Inactive*/
						pool->chunk[i].pattern=PATTERN_INACTIVE;
					}
					else if(pool->chunk[i].req_sum_all>=(req_in_window/pool->chunk_win)*2)
					{
						/*INTENSIVE*/
						i_intensive++;
						if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Intensive Read*/
							pool->chunk[i].pattern=PATTERN_INTENSIVE_READ;
						}
						else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Intensive Write*/
							pool->chunk[i].pattern=PATTERN_INTENSIVE_WRITE;
						}
						else
						{
							/*Intensive Hybrid*/
							pool->chunk[i].pattern=PATTERN_INTENSIVE_HYBRID;
						}
					}
					else if((pool->chunk[i].seq_size_all/pool->chunk[i].req_size_all)>=pool->threshold_cbr)//
					{
						/*SEQUENTIAL*/
						if(((long double)pool->chunk[i].seq_sum_all/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_car)
						{
							i_sequential++;
							if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Read*/
								pool->chunk[i].pattern=PATTERN_SEQUENTIAL_READ;
							}
							else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
							{
								/*Sequential Write*/
								pool->chunk[i].pattern=PATTERN_SEQUENTIAL_WRITE;
							}
							else
							{
								/*Intensive Hybrid*/
								pool->chunk[i].pattern=PATTERN_SEQUENTIAL_HYBRID;
							}
						}
						else
						{
							/*Semi-Sequential*/
							pool->chunk[i].pattern=PATTERN_SEMI_SEQUENTIAL;
						}
					}
					
					else
					{
						if(((long double)pool->chunk[i].req_sum_read/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Random Read*/
							pool->chunk[i].pattern=PATTERN_RANDOM_READ;
						}
						else if(((long double)pool->chunk[i].req_sum_write/(long double)pool->chunk[i].req_sum_all)>=pool->threshold_rw)
						{
							/*Random Write*/
							pool->chunk[i].pattern=PATTERN_RANDOM_WRITE;
						}
						else
						{
							/*Random Hybrid*/
							pool->chunk[i].pattern=PATTERN_RANDOM_HYBRID;
						}
					}
					//Only record limited information (the first SIZE_ARRY windows)
					if(pool->window_sum<SIZE_ARRAY)
					{
						pool->chunk[i].history_pattern[pool->window_sum]=pool->chunk[i].pattern;

						pool->pattern_inactive[pool->window_sum]=i_inactive/(double)chunk_num;
						pool->pattern_intensive[pool->window_sum]=i_intensive/(double)chunk_num;
						pool->pattern_sequential[pool->window_sum]=i_sequential/(double)chunk_num;
					}
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
				i_inactive=0;
				i_sequential=0;
				i_intensive=0;

				//accessed chunks in each window
				memset(pool->record,0,sizeof(struct record_info)*pool->chunk_sum);
				printf("pool->chunk_win=%d\n",pool->chunk_win);
				pool->chunk_win=0;
			}//if
		}//if
	}//while

	print_statistics(pool);

	fclose(pool->file_trace);
	fclose(pool->file_output);
	
	free(pool->chunk);
	free(pool->map);
	free(pool->req);
	free(pool);

	return SUCCESS;
}