import com.sun.management.ThreadMXBean
import java.io.File
import java.lang.management.ManagementFactory
import java.util.Locale
import kotlin.math.max

object Benchmark {
    private const val WARMUP_ROUNDS = 3
    private const val TIMED_ROUNDS = 5
    private const val MIB = 1024.0 * 1024.0
    private const val MIN_ROUND_NANOS = 150_000_000L

    @Volatile
    private var sink: Any? = null

    @Volatile
    private var intSink: Int = 0

    private val threadBean: ThreadMXBean? =
        (ManagementFactory.getThreadMXBean() as? ThreadMXBean)?.takeIf {
            it.isThreadAllocatedMemorySupported
        }?.also {
            if (!it.isThreadAllocatedMemoryEnabled) {
                it.isThreadAllocatedMemoryEnabled = true
            }
        }

    data class Case(
        val name: String,
        val bytesPerOp: Long,
        val block: () -> Unit,
    )

    private data class RoundResult(
        val mibPerSec: Double,
        val bytesAllocatedPerOp: Long,
    )

    fun blackhole(value: Any?) {
        sink = value
    }

    fun blackhole(value: Int) {
        intSink = value
    }

    fun deterministicBytes(size: Int, seed: Long = 0x5EED_1234_5678_9ABCL): ByteArray {
        val out = ByteArray(size)
        var state = seed
        for (i in out.indices) {
            state = state * 6364136223846793005L + 1442695040888963407L
            out[i] = (state ushr 56).toByte()
        }
        return out
    }

    fun requireTrue(condition: Boolean, message: () -> String) {
        if (!condition) {
            throw AssertionError(message())
        }
    }

    fun run(args: Array<String>, cases: List<Case>) {
        val csvOut = args.firstOrNull()?.let { File(it) }
        val csvRows = ArrayList<String>()
        csvRows.add("workload,round,mib_per_sec,bytes_per_op")

        println(String.format(Locale.US, "%-32s %12s %14s", "Workload", "MiB/s (med)", "Bytes/op (med)"))
        println("-".repeat(60))

        for (bench in cases) {
            val iters = calibrateIterations(bench.block)
            repeat(WARMUP_ROUNDS) {
                runBatch(iters, bench.block)
            }

            val rounds = ArrayList<RoundResult>(TIMED_ROUNDS)
            for (round in 1..TIMED_ROUNDS) {
                val tid = Thread.currentThread().id
                val allocBefore = threadBean?.getThreadAllocatedBytes(tid) ?: -1L
                val startNs = System.nanoTime()
                runBatch(iters, bench.block)
                val elapsedNs = max(1L, System.nanoTime() - startNs)
                val allocAfter = threadBean?.getThreadAllocatedBytes(tid) ?: -1L

                val totalBytes = bench.bytesPerOp.toDouble() * iters
                val mibPerSec = (totalBytes / MIB) / (elapsedNs / 1_000_000_000.0)
                val bytesAllocPerOp = if (allocBefore >= 0 && allocAfter >= allocBefore) {
                    (allocAfter - allocBefore) / iters
                } else {
                    -1L
                }
                rounds.add(RoundResult(mibPerSec, bytesAllocPerOp))
                csvRows.add(
                    String.format(
                        Locale.US,
                        "%s,%d,%.2f,%d",
                        bench.name,
                        round,
                        mibPerSec,
                        bytesAllocPerOp,
                    ),
                )
            }

            val medianThroughput = rounds.map { it.mibPerSec }.sorted()[TIMED_ROUNDS / 2]
            val medianAlloc = rounds.map { it.bytesAllocatedPerOp }.sorted()[TIMED_ROUNDS / 2]
            println(String.format(Locale.US, "%-32s %12.2f %14d", bench.name, medianThroughput, medianAlloc))
        }

        if (csvOut != null) {
            csvOut.parentFile?.mkdirs()
            csvOut.writeText(csvRows.joinToString("\n", postfix = "\n"))
        }
    }

    private fun calibrateIterations(block: () -> Unit): Int {
        var iters = 1
        while (true) {
            val start = System.nanoTime()
            runBatch(iters, block)
            val elapsed = System.nanoTime() - start
            if (elapsed >= MIN_ROUND_NANOS || iters >= 1_000_000) {
                return iters
            }
            iters = if (elapsed < 5_000_000L) {
                iters * 8
            } else {
                iters * 2
            }
        }
    }

    private fun runBatch(iters: Int, block: () -> Unit) {
        for (i in 0 until iters) {
            block()
        }
    }
}
