#!/bin/bash

export AFL_NO_UI=1 
export AFL_NO_AFFINITY=1

timeout 12h /afl/afl-fuzz -m none -M afl -i seeds/ -o /out -- ./ftfuzzer @@ &

sleep 10
timeout 12h ~/.cargo/bin/symcc_fuzzing_helper -o /out -a afl -n symcc -- /src/benchmarks_symcc/freetype2_ftfuzzer/ftfuzzer @@ &

wait
