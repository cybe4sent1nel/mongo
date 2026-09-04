#!/bin/sh
# Stands in for the developer's real editor (code / subl / atom / gvim ...).
# Records exactly what Next.js spawned it with.
printf '%s spawned with argv:' "$(date -u +%H:%M:%S)" >> /tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/editor_spawns.log
for a in "$@"; do printf ' [%s]' "$a" >> /tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/editor_spawns.log; done
printf '\n' >> /tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/editor_spawns.log
exit 0
