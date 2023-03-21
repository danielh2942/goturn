# GoTurn

This is an implementation of [RFC5766](https://www.ietf.org/rfc/rfc5766.txt)
for my university final year computer science project written in golang. It
probably will not be particularly secure as it is written as a speed comparison
against the better written/defined coturn project.

The project itself is an attempt at calculating jitter/latency during RTC
transactions. It initially was going to extend coturn and utilize eBPF but this
proved to be somewhat difficult to achieve within the provided timeframe so
instead you get to see my implementation of TURN in it's entirety.

This may or may not be useful to you.

I may return to it or I may not, time will tell :)
(However making the eBPF change to coturn is a personal goal I would
still like to achieve so idk lol)

It will also have a partial implementation of
[RFC5389](https://www.rfc-editor.org/rfc/rfc5389) as it is required to an
extent to allow one to actually implement TURN
