/*************************************************************************
	> File Name: seq_detector.h
	> Author: Xuchao Xie
	> Mail: xiexuchao@foxmail.com
	> Created Time: Sat 27 Feb 2016 11:47:23 PM CST
 ************************************************************************/

#ifndef _SEQ_DETECTOR_H
#define _SEQ_DETECTOR_H

#include "pool.h"

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

void seq_detection(struct pool_info *pool);
void flush_stream(struct pool_info *pool);

#endif
