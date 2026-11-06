package main

import (
    "flag"
    "fmt"
    "math/rand"
    "time"

    "github.com/ahenzinger/simplepir/pir"
)

func main() {
    N := flag.Uint64("N", 1024, "record count")
    d := flag.Uint64("d", 1, "number of 16-bit blocks per record")
    n := flag.Uint64("n", 1024, "LWE dimension")
    x := flag.Uint64("x", 1000, "number of PIR querie to run")

    const w uint64 = 16
    const logq uint64 = 64

    // SimplePIR prototype uses the plaintext modulus p both for arithmetic and
    // for determining database packing. To model databases composed of 16-bit
    // blocks, we fix p = 2^16 so that each block occupies exactly one
    // plaintext element. While larger plaintext moduli could be used without
    // changing the logical data representation, doing so would alter the
    // prototype's packing strategy and database dimensions, making performance
    // comparisons less meaningful.
    const p uint64 = 1 << w

    flag.Parse()

    fmt.Printf("Using: N=%d; d=%d; p=%d; logq=%d; n=%d; x=%d\n", *N, *d, p, logq, *n, *x)

    l, m := pir.ApproxSquareDatabaseDims(
        *N,      // number of records
        *d * w,  // bits per record
        p,       // 2^16 => 1 plaintext element per 16-bit block
    )

    fmt.Printf("DB rows (l)=%d; DB cols (m)=%d; Packed elements=%d\n", l, m, l*m)

    // the SimplePIR prototype uses a fixed Gaussian sampler with sigma = 6.4 and
    // does not expose sigma as a configurable parameter. Since our implementation
    // requires larger noise parameters to achieve comparable security levels,
    // this experimental setup should be viewed as favorable to the prototype.
    params := pir.Params{
        N: *n,          // LWE secret dimension
        L: l,           // DB height
        M: m,           // DB width
        Logq: logq,    // (logarithm of) ciphertext modulus
        P: p,           // plaintext modulus 
    }

    scheme := pir.SimplePIR{}

    // pre-generate X many indices to query
    fmt.Printf("Preselecting indices to query\n")
    indices := make([]uint64, *x)
    rng := rand.New(rand.NewSource(1))
    for i := range indices {
        indices[i] = uint64(rng.Int63n(int64(*N)))
    }

    // Benchmark-only fast path.
    // The prototype materializes and processes the full offline state
    // despite the benchmark never validating PIR correctness. We replace
    // the database, public matrix A, and offline hint H with correctly
    // sized zero matrices so that Query/Answer/Recover execute with the
    // expected dimensions while avoiding hours of unnecessary setup work.

    fmt.Printf("Creating test db, A, hint_c\n")

    db := pir.SetupDB(*N, *d * w, &params)
    db.Info.Basis = 16
    db.Info.Squishing = 4
    db.Info.Cols = params.M 
    db.Data = pir.MatrixZeros(params.L, (params.M + 3) / 4)

    shared := pir.MakeState(
        pir.MatrixZeros(params.M, params.N),
    )
    offline := pir.MakeMsg(
        pir.MatrixZeros(params.L, params.N),
    )

    var sink uint64 

    // start benchmarking
    fmt.Printf("Starting benchmarks\n")
    var queryTime time.Duration
    var answerTime time.Duration
    var recoverTime time.Duration

    benchStart := time.Now()

    for _, idx := range indices {
        t := time.Now()
        clientState, q := 
            scheme.Query(
                idx,
                shared,
                params,
                db.Info,
            )
        queryTime += time.Since(t)

        t = time.Now()
        answer :=
            scheme.Answer(
                db,
                pir.MakeMsgSlice(q),
                pir.MakeState(),
                shared,
                params,
            )
        answerTime += time.Since(t)

        t = time.Now()
        recovered :=
            scheme.Recover(
                idx,
                0,
                offline,
                q,
                answer,
                shared,
                clientState,
                params,
                db.Info,
            )
        recoverTime += time.Since(t)

        sink += recovered
    }

    wallTime := time.Since(benchStart)
    fmt.Printf("Done! Wall total: %v\n", wallTime)

    fmt.Printf("\nAggregate timings\n")
    fmt.Printf("Query total:   %v\n", queryTime)
    fmt.Printf("Answer total:  %v\n", answerTime)
    fmt.Printf("Recover total: %v\n", recoverTime)
    totalTime := queryTime + answerTime + recoverTime
    fmt.Printf("Online total:  %v\n", totalTime)

    fmt.Printf("\nPer-query timing\n")
    fmt.Printf("Query:   %v avg\n", queryTime/time.Duration(*x))
    fmt.Printf("Answer:  %v avg\n", answerTime/time.Duration(*x))
    fmt.Printf("Recover: %v avg\n", recoverTime/time.Duration(*x))
    fmt.Printf("Total:   %v avg\n", totalTime/time.Duration(*x))
    fmt.Printf("Queries/sec: %.2f\n", float64(*x)/totalTime.Seconds())
}
