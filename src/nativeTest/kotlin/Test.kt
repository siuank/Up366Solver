import aes.AESCipherCBC
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlin.test.Test


private val key = byteArrayOf(64, -112, 77, -120, 25, -107, -25, -109, -61, -83, -20, 50, -99, -19, -58, -80)

@OptIn(ExperimentalForeignApi::class, ExperimentalStdlibApi::class)
@Test
fun test() {
    val encryption = AESCipherCBC()
    encryption.init(false, key, key)
    var plaintext = "This is a test".encodeToByteArray()
    if (plaintext.size % 16 != 0) {
        plaintext = plaintext.copyOf(plaintext.size + (16 - plaintext.size % 16))
    }
    val ciphertext = encryption.doFinal(plaintext, 0, plaintext.size)!!
    encryption.init(true, key, key)
    val decryptedText = encryption.doFinal(ciphertext, 0, ciphertext.size)!!
    println("${plaintext.toHexString()}: ${plaintext.toKString()}")
    println(ciphertext.toHexString())
    println("${decryptedText.toHexString()}: ${decryptedText.toKString()}")
}