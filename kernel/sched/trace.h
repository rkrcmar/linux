#if !defined(_TRACE_SCHED_H_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCHED_H_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched

TRACE_EVENT(sched_update_nr_running,

	TP_PROTO(int cpu, unsigned long value, long change),

	TP_ARGS(cpu, value, change),

	TP_STRUCT__entry(
		__field(long,          change)
		__field(unsigned long, value)
		__field(int,           cpu)
	),

	TP_fast_assign(
		__entry->cpu    = cpu;
		__entry->value  = value;
		__entry->change = change;
	),

	TP_printk("cpu=%u value=%lu (change=%ld)",
			__entry->cpu, __entry->value, __entry->change)
);

#endif

// TODO: wtf is wrong with this?
//#undef TRACE_INCLUDE_PATH
//#define TRACE_INCLUDE_PATH .
//#undef TRACE_INCLUDE_FILE
//#define TRACE_INCLUDE_FILE trace
//
///* This part must be outside protection */
//#include <trace/define_trace.h>
