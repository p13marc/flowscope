# Migrating from 0.25 to 0.26

0.26 is the *truncation, orientation & bounded tables* cycle. It makes
flowscope count and parse packets cut by a capture snap length instead
of skipping them, reports byte counts as wire and IP lengths instead of
captured lengths, gates parser lifecycle output by `EventMask` and
pause like every other event, orients every output and detector by the
flow's **initiator** instead of the address-sorted key, and bounds the
per-key rate tables.

Each section below names the issue it comes from, what changed, and
what to do about it.
