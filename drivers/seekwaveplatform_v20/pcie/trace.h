/*
 * Copyright (C) 2022 Seekwave Tech Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM skwpcie

#if !defined(__SKWPCIE_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __SKWPCIE_TRACE_H__

#include <linux/tracepoint.h>

/*
TRACE_EVENT(skw_edma_channel_irq_handler,
	    TP_PROTO(int line, char *str, u64 val),
	    TP_ARGS(line, str, val),

	    TP_STRUCT__entry(
		__field(int, line)
		__field(char *, str)
		__field(u64, val)
	    ),

	    TP_fast_assign(
		__entry->line = line;
		__entry->str = str;
		__entry->val = val;
	    ),

	    TP_printk("line: %d, %s=0x%llx",
		__entry->line, __entry->str, __entry->val)
);
*/
TRACE_EVENT(skw_edma_channel_irq_handler,
	    TP_PROTO(int line, char *str, u64 val, u64 val1, u64 val2),
	    TP_ARGS(line, str, val, val1, val2),

	    TP_STRUCT__entry(
		__field(int, line)
		__field(char *, str)
		__field(u64, val)
		__field(u64, val1)
		__field(u64, val2)
	    ),

	    TP_fast_assign(
		__entry->line = line;
		__entry->str = str;
		__entry->val = val;
		__entry->val1 = val1;
		__entry->val2 = val2;
	    ),

	    TP_printk("line: %d, %s, 0x%llx, %lld, %lld",
		__entry->line, __entry->str, __entry->val,__entry->val1, __entry->val2)
);

#endif /* !_SKWPCIE_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
