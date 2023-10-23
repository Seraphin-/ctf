# RCA (Misc 476, 23 solves)

We're given a cellular automaton-looking algorithm and an array state that we need to "rewind" 160 steps. Fortunately the algorithm is pretty simple:
- Divide the array into squares of 4, offset by (-1, -1) on odd numbered iterations
- If there are not 2 "alive" cells, flip the states of each
- If there are now 3 "alive" cells, reverse the order of the square (rotate in 2d space)

The only change we need to make to run it backwards is reverse the order if 1 cell is "alive" first. The flag is visually encoded in the resulting state after rewinding.

I thought I had to rewind all the way from 160760160 to 0 so I wrote my solver in C++, and after letting it run for an hour and getting garbage I realized I was only supposed to go to 160760000...

Flag: `X-MAS{A_SMALL_WORLD_INSIDE_YOUR_BROWSER}`
