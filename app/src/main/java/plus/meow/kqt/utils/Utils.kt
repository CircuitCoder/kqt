package plus.meow.kqt.utils

import android.content.Context
import android.widget.Toast

/**
 * Utility functions and types.
 */

/**
 * A monadic Result type that represents either success or failure.
 *
 * @param T The type of the success value
 * @param E The type of the error
 */
sealed class Result<T, E> {
    data class Ok<T, E>(val value: T) : Result<T, E>()
    data class Err<T, E>(val error: E) : Result<T, E>() {
        /**
         * Show a toast message with the error and optionally invoke a callback.
         *
         * @param context Android context for showing toast messages
         * @param onDismiss Optional callback to invoke after showing the toast
         */
        fun toast(context: Context, onDismiss: (() -> Unit)? = null) {
            Toast.makeText(context, error.toString(), Toast.LENGTH_LONG).show()
            onDismiss?.invoke()
        }
    }

    /**
     * Functor map: Transform the success value while preserving errors.
     */
    fun <U> map(f: (T) -> U): Result<U, E> {
        return when (this) {
            is Ok -> Ok(f(value))
            is Err -> Err(error)
        }
    }

    /**
     * Map the error type.
     */
    fun <F> mapErr(f: (E) -> F): Result<T, F> {
        return when (this) {
            is Ok -> Ok(value)
            is Err -> Err(f(error))
        }
    }

    /**
     * Monadic bind (flatMap): Chain operations that return Results.
     * Works with both regular and suspend functions through inlining.
     */
    suspend inline fun <U> bind(crossinline f: suspend (T) -> Result<U, E>): Result<U, E> {
        return when (this) {
            is Ok -> f(value)
            is Err -> Err(error)
        }
    }

    inline fun unwrapOrElse(f: (E) -> T): T {
        return when (this) {
            is Ok -> value
            is Err -> f(error)
        }
    }

    /**
     * Get the success value or null if error.
     */
    fun getOrNull(): T? {
        return when (this) {
            is Ok -> value
            is Err -> null
        }
    }

    /**
     * Get the error or null if success.
     */
    fun errorOrNull(): E? {
        return when (this) {
            is Ok -> null
            is Err -> error
        }
    }

    companion object {
        fun <T, E> ok(value: T): Result<T, E> = Ok(value)
        fun <T, E> err(error: E): Result<T, E> = Err(error)
    }
}


