-----
event:
-----
event is an example to receiving tsn multicast event and create a alarm for user.
It is require to run the phc2sys command as background to sync ptp wit system clock.

like:

./phc2sys -s /dev/ptp0 -O 2

or:

./phc2sys -s /dev/ptp0 -w

------
Alarm:
------
There are three APIs to create alarms. All APIs are in the libtsn.so.

Create a blocking alarm. Never return:

int set_period_alarm(uint64_t ts, uint64_t offset, uint64_t cycle,
		     void (*callback_func)(void *data), void *data)

Create a non-blocking alarm:

pthread_t *create_alarm_common(uint64_t ts, uint32_t offset, uint32_t cycle,
			       void (*callback_func)(void *data), void *data)

Create a internal tsn multicast alarm:

int create_alarm_thread(uint64_t ts, uint32_t offset, uint32_t cycle,
		        uint32_t iface, uint32_t infotype,
			void (*callback_func)(void *data), void *data)

ts:		The require to be current time or future time.
offset:		base on the ts, offset of it.
cycle:		the period time.
callback_func:	callback function user provide.
data:		parameter of callback function.

In the event.c you can test create blocking alarm by run:

event -t 1

In the event.c you can test create non-blocking alarm by run:

event -t 2

At same time you can run the tsntool to set Qbv enable and create another
internal alarm for the tsn Qbv alarm by gate list cycle.

----------
multicast:
----------
Ready to receiving tsn multicast. You need to create a alarm_info structure.
event.c provide the example:

	alarminfo.qbvmc.callback_func = handle_alarm_qbv;
	alarminfo.qbvmc.data = &a;
	alarminfo.qcimc.callback_func = handle_alarm_qci;
	alarminfo.qcimc.data = &b;

	wait_tsn_multicast(&alarminfo);

at last call wait_tsn_multicast(&alarminfo). will never return and keep waiting
the multicast message.

------------
timestamping
------------
This app is use for sending frames and get timestamping for the frames.
Here are some command examples:

repeat send/receive frames with timestamping:
./timestamping -i eno0 -c 0

send 2 frames
./timestamping -i eno0 -c 2

fully send 2 frames without waiting the timestamping event.
./timestamping -i eno0 -c 2 -f

repeat fully sending frames
./timestamping -i eno0 -c 0 -f

only receive frame with timestamping repeat
./timestamping -i eno0 -r

