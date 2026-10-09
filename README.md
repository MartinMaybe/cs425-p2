# Project X

- Name: John Doe
- Email: johndoe@u.boisestate.edu
- Class: CS123-001

## Known Bugs or Issues

TODO: Are there any known issues?

## Experience

TODO: Describe your experience with the project (struggles, breakthroughs, etc.).

## Analysis

TODO: Provide your analysis of the results. If the assignment does not require
analysis, you can remove this section.

Here is an example of how to include a plot in your README:

![Example Image](scripts/example_plot.png)

## Transfer implementation

The protocol is split into three layers:

- `src/packet.c` encodes and validates wire packets without I/O.
- `src/gbn.c` implements sender and receiver state machines. Events take
  explicit millisecond timestamps and return packet, payload, completion, and
  timer actions.
- `src/file_packets.c` reads files into sequenced DATA packets.
- `src/transfer.c` handles relay registration, UDP, polling, and the monotonic
  clock, and applies actions from the state machines.

## Results

Each run transferred the 1 MiB `1mib.bin` file through `cs425_relay.py
--delay 50` using the default 250 ms retransmission timeout. Every received
copy matched the input with `cmp`. Times are the sender's `time` real values;
throughput is 1024 KiB divided by the mean time.

| Window | Loss | Mean time (s) | Throughput (KiB/s) |
|-------:|-----:|--------------:|-------------------:|
| 1  | 0% | 105.582 | 9.70 |
| 16 | 0% | 6.751   | 151.67 |
| 1  | 5% | 134.152 | 7.63 |
| 16 | 5% | 23.737  | 43.14 |


1. The table’s window-1 no-loss mean is 105.582 seconds. Divide by 1025 packets 
then convert to milliseconds, we get about 103 ms per round trip. If the relay 
adds 100 ms, we get around 3 ms extra. This time comes from the handling of 
packets and ACKs, plus operating-system scheduling.

2. Doing 105.582/6.751 we get that it’s about 15.6 times faster, almost 16. With 
16 packets in flight, the sender can keep transferring while it waits for acknowledgments 
instead of pausing after every packet.

3. With window 1, a timeout resends just the one packet that’s still waiting for 
an ACK. With window 16, a lost packet holds up the receiver’s progress. It discards 
later packets until the gap is filled and the sender has to resend the whole outstanding 
window. That extra retransmission work makes loss hurt window 16 more.
