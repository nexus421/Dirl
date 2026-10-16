package bayern.kickner.dirl.web

import bayern.kickner.dirl.ssh.MetricsSample
import java.util.Locale

/** Which value of a [MetricsSample] a chart shows, in percent. */
enum class ChartMetric(val label: String, val value: (MetricsSample) -> Double?) {
    CPU("CPU", { it.cpuPercent }),
    MEM("RAM", { s -> if (s.memTotalKiB > 0) s.memUsedKiB * 100.0 / s.memTotalKiB else null }),
    SWAP("Swap", { s -> if (s.swapTotalKiB > 0) s.swapUsedKiB * 100.0 / s.swapTotalKiB else null }),
}

/** The longest time span a chart shows. */
const val CHART_WINDOW_MILLIS = 24L * 3600 * 1000

/**
 * Left edge of a chart: 24 hours ago, or the oldest sample if the history is shorter. A fresh history fills the
 * chart instead of being a sliver at its right edge.
 */
fun chartStart(samples: List<MetricsSample>, now: Long): Long =
    maxOf(now - CHART_WINDOW_MILLIS, samples.firstOrNull()?.time ?: now)

/**
 * Renders the history of one metric as a small SVG line chart, 0 to 100 percent from [chartStart] to [now].
 *
 * The SVG is built from numbers only, no text from the host or the vault goes into it, so it cannot carry markup.
 * It is served as its own resource and embedded with `<img>`, which keeps scripts out of it as well.
 *
 * @param samples History, oldest first.
 * @param now Unix milliseconds of the right edge.
 */
fun renderChart(samples: List<MetricsSample>, metric: ChartMetric, now: Long): String {
    val width = 600.0
    val height = 110.0
    val start = chartStart(samples, now)
    val windowMillis = (now - start).coerceAtLeast(1)
    val points = samples.mapNotNull { s ->
        val v = metric.value(s) ?: return@mapNotNull null
        if (s.time < start) return@mapNotNull null
        val x = (s.time - start) * width / windowMillis
        val y = height - v.coerceIn(0.0, 100.0) * (height - 4) / 100.0 - 2
        "%.1f,%.1f".format(Locale.ROOT, x, y)
    }
    val grid = listOf(25, 50, 75).joinToString("") { p ->
        val y = height - p * (height - 4) / 100.0 - 2
        """<line x1="0" x2="$width" y1="${"%.1f".format(Locale.ROOT, y)}" y2="${"%.1f".format(Locale.ROOT, y)}" class="grid"/>"""
    }
    val line = if (points.size < 2) "" else {
        // The area starts below the first point, not at the left edge, so a short history is not drawn as a ramp.
        val area = "${points.first().substringBefore(',')},$height " + points.joinToString(" ") + " ${points.last().substringBefore(',')},$height"
        """<polygon points="$area" class="area"/><polyline points="${points.joinToString(" ")}" class="line"/>"""
    }
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $width $height" preserveAspectRatio="none">""" +
        """<style>.grid{stroke:#8a93a3;stroke-opacity:.25;stroke-width:1;vector-effect:non-scaling-stroke}""" +
        """.line{fill:none;stroke:#2f6fed;stroke-width:2;vector-effect:non-scaling-stroke;stroke-linejoin:round}""" +
        """.area{fill:#2f6fed;fill-opacity:.12}""" +
        """@media (prefers-color-scheme: dark){.line{stroke:#5b8dff}.area{fill:#5b8dff}}</style>""" +
        grid + line + "</svg>"
}
