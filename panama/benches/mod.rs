//! Basic benchmarks
#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    panama::Panama;
    panama_bench1_16b 16;
    panama_bench2_256b 256;
    panama_bench3_1kib 1024;
    panama_bench4_16kib 16384;
);
