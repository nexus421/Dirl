package bayern.kickner.dirl.vault

/** Minimum length of a passphrase that is not made of separate words. */
const val MIN_PASSPHRASE_LENGTH = 20

/** Minimum number of distinct words for a Diceware style passphrase. */
const val MIN_PASSPHRASE_WORDS = 5

/**
 * Checks a new vault passphrase: at least [MIN_PASSPHRASE_LENGTH] characters, or at least [MIN_PASSPHRASE_WORDS]
 * distinct words of three or more letters (Diceware), separated by spaces, hyphens, dots or underscores.
 *
 * The passphrase protects the vault against offline attacks on a leaked backup, so it is the one secret that
 * really has to be strong. It lives in the password manager, typing effort does not matter.
 *
 * Only length or word count is checked, not randomness, so `aaaaaaaaaaaaaaaaaaaa` passes. Deliberate: the passphrase is
 * set by someone who already has full access, and a simple rule cannot stop someone who wants a weak one.
 *
 * @return `null` if acceptable, otherwise a reason to show to the user.
 */
fun checkPassphrase(passphrase: CharArray): String? {
    if (passphrase.size >= MIN_PASSPHRASE_LENGTH) return null

    val words = String(passphrase).split(Regex("[\\s\\-._]+")).filter { it.length >= 3 }.toSet()
    val enoughWords = words.size >= MIN_PASSPHRASE_WORDS
    return if (enoughWords) null
    else "Use at least $MIN_PASSPHRASE_LENGTH characters or $MIN_PASSPHRASE_WORDS distinct Diceware words"
}
