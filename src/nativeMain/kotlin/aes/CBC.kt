package aes


internal class CBC(val embeddedCipher: AESCrypt) {
    var r: ByteArray = ByteArray(16)
    private val k: ByteArray = ByteArray(16)
    private var rSave: ByteArray? = null
    lateinit var iv: ByteArray

    val feedback: String?
        get() = "CBC"

    fun init(decrypting: Boolean, key: ByteArray?, iv: ByteArray?) {
        if (key != null && iv != null && iv.size == 16) {
            this.iv = iv
            this.reset()
            this.embeddedCipher.init(decrypting, key)
        } else {
            throw IllegalArgumentException("Invalid parameters specified")
        }
    }

    fun reset() {
//        System.arraycopy(this.iv, 0, this.r, 0, blockSize)
        this.iv.copyInto(this.r)
    }

    fun save() {
        if (this.rSave == null) {
            this.rSave = ByteArray(blockSize)
        }

        this.rSave?.copyInto(this.r, 0, 0, blockSize)
    }

    fun restore() {
        this.rSave?.copyInto(this.r, 0, 0, blockSize)
    }

    fun encrypt(plain: ByteArray, plainOffset: Int, plainLen: Int, cipher: ByteArray, cipherOffset: Int): Int {
        if (plainLen <= 0) {
            return plainLen
        } else {
//            ArrayUtil.blockSizeCheck(plainLen, blockSize)
//            ArrayUtil.nullAndBoundsCheck(plain, plainOffset, plainLen)
//            ArrayUtil.nullAndBoundsCheck(cipher, cipherOffset, plainLen)
            return this.implEncrypt(plain, plainOffset, plainLen, cipher, cipherOffset)
        }
    }

    private fun implEncrypt(
        plain: ByteArray,
        plainOffset: Int,
        plainLen: Int,
        cipher: ByteArray,
        cipherOffset: Int
    ): Int {
        var plainOffset = plainOffset
        var cipherOffset = cipherOffset
        val endIndex = plainOffset + plainLen
        while (plainOffset < endIndex) {
            for (i in 0..<blockSize) {
                this.k[i] = (plain[i + plainOffset].toInt() xor this.r[i].toInt()).toByte()
            }

            this.embeddedCipher.encryptBlock(this.k, 0, cipher, cipherOffset)
//            System.arraycopy(cipher, cipherOffset, this.r, 0, blockSize)
            cipher.copyInto(r, 0, cipherOffset, plainOffset + blockSize)
            plainOffset += blockSize
            cipherOffset += blockSize
        }

        return plainLen
    }

    fun decrypt(cipher: ByteArray, cipherOffset: Int, cipherLen: Int, plain: ByteArray, plainOffset: Int): Int {
        if (cipherLen <= 0) {
            return cipherLen
        } else {
//            ArrayUtil.blockSizeCheck(cipherLen, blockSize)
//            ArrayUtil.nullAndBoundsCheck(cipher, cipherOffset, cipherLen)
//            ArrayUtil.nullAndBoundsCheck(plain, plainOffset, cipherLen)
            return this.implDecrypt(cipher, cipherOffset, cipherLen, plain, plainOffset)
        }
    }

    private fun implDecrypt(
        cipher: ByteArray,
        cipherOffset: Int,
        cipherLen: Int,
        plain: ByteArray,
        plainOffset: Int
    ): Int {
        var cipherOffset = cipherOffset
        var plainOffset = plainOffset
        val endIndex = cipherOffset + cipherLen
        while (cipherOffset < endIndex) {
            this.embeddedCipher.decryptBlock(cipher, cipherOffset, this.k, 0)

            for (i in 0..<blockSize) {
                plain[i + plainOffset] = (this.k[i].toInt() xor this.r[i].toInt()).toByte()
            }

//            System.arraycopy(cipher, cipherOffset, this.r, 0, blockSize)
            cipher.copyInto(r, 0, cipherOffset, plainOffset + blockSize)
            cipherOffset += blockSize
            plainOffset += blockSize
        }

        return cipherLen
    }

    companion object {
        const val blockSize: Int = 16
    }
}