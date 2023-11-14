package com.decathlon.cg.benchmarks;

import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.LinuxPerfNormProfiler;
import org.openjdk.jmh.profile.PausesProfiler;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public class Main {
    public static void main(String[] args) throws RunnerException {
        Options options = new OptionsBuilder()
                .addProfiler(GCProfiler.class.getName())
     //           .addProfiler(LinuxPerfNormProfiler.class)
                .addProfiler(PausesProfiler.class)
                .resultFormat(ResultFormatType.TEXT)
                .resultFormat(ResultFormatType.CSV)
                .build();

        new Runner(options).run();


    }
}