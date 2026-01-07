# Border Binary Recognition
A simple tool to recognize border binaries in IoT firmware

## PreProcess
load all elf binaries (executables), get all binaries' libraries

## How to Filter
1. PreCheck: check if there is "socket" function symbol in target binary;
2. Use IDA tool to check if there is any logic about socket establishing (eg: socket -> bind -> listen -> accept).

## TODO:
1. add multi-thread supported to phrase2-4.
2. maybe we can leverage database to store analysis results.
3. maybe have other more precise check algorithm.
  - cross function
