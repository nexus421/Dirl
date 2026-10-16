package bayern.kickner.dirl.web

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.path
import kotlinx.html.p

private const val TAG = "ErrorPages"

/**
 * Styled pages for unknown paths, wrong methods and unexpected exceptions. An exception is logged with its stack
 * trace, the page only says that something went wrong, so no internals reach the browser.
 */
fun Application.installErrorPages() {
    install(StatusPages) {
        status(HttpStatusCode.NotFound, HttpStatusCode.MethodNotAllowed) { call, status ->
            call.errorPage(status, "Page not found", "This address does not exist in Dirl.")
        }
        exception<Throwable> { call, cause ->
            staticLog(KLogger.Level.ERROR, TAG) { "Request ${call.request.path()} failed: ${cause.stackTraceToString()}" }
            call.errorPage(HttpStatusCode.InternalServerError, "Something went wrong", "The error was logged. Try again, or check the log on the server.")
        }
    }
}

private suspend fun ApplicationCall.errorPage(status: HttpStatusCode, title: String, text: String) {
    // Error pages also render for paths outside the guards, so the session is looked up here instead of assumed.
    val session = if (attributes.contains(SessionKey)) attributes[SessionKey] else null
    page(title, session, status = status) {
        pageHeader(title)
        card {
            p("muted") { +text }
            linkButton("/", "Back to the overview", "primary")
        }
    }
}
