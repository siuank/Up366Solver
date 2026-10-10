package aes

import kotlin.math.min

class AESCipherCBC {
    private var buffer: ByteArray
    private var blockSize = 0
    private var unitBytes = 0
    private var buffered = 0
    private var minBytes = 0
    private var diffBlocksize = 0
    private var cipher = CBC(AESCrypt())
    private var cipherMode = 0
    private var decrypting = false

    init {
        this.blockSize = 16
        this.unitBytes = 16
        this.diffBlocksize = 16
        this.buffer = ByteArray(this.blockSize * 2)
    }

    private fun getNumOfUnit(mode: String, offset: Int, blockSize: Int): Int {
        var result = blockSize
        if (mode.length > offset) {
            val numInt: Int
            try {
                numInt = (mode.substring(offset)).toInt()
                result = numInt shr 3
            } catch (var6: NumberFormatException) {
                throw RuntimeException("Algorithm mode: " + mode + " not implemented")
            }

            if (numInt % 8 != 0 || result > blockSize) {
                throw RuntimeException("Invalid algorithm mode: " + mode)
            }
        }

        return result
    }



    fun getOutputSize(inputLen: Int): Int {
        return this.getOutputSizeByOperation(inputLen, true)
    }

    private fun getOutputSizeByOperation(inputLen: Int, isDoFinal: Boolean): Int {
        var totalLen = this.buffered
        totalLen = Math.addExact(totalLen, inputLen)
        if (!this.decrypting) {
            if (this.unitBytes != this.blockSize) {
                if (totalLen < this.diffBlocksize) {
                    totalLen = this.diffBlocksize
                } else {
                    val residue = (totalLen - this.diffBlocksize) % this.blockSize
                    totalLen = Math.addExact(totalLen, this.blockSize - residue)
                }
            } else {
//                totalLen = Math.addExact(totalLen, this.padding.padLength(totalLen))
            }
        }

        return totalLen
    }

    fun getIV(): ByteArray? {
        val iv: ByteArray? = this.cipher.iv
        return iv?.copyOf()
    }



    fun init(decrypting: Boolean, key: ByteArray, iv: ByteArray) {
        this.decrypting = decrypting
        val keyBytes = getKeyBytes(key)
        var ivBytes: ByteArray?

        try {
            if (iv.size != this.blockSize) throw RuntimeException("IV must be " + this.blockSize + " bytes long")
            ivBytes = iv
            this.buffered = 0
            this.diffBlocksize = this.blockSize
            this.cipher.init(this.decrypting, keyBytes, ivBytes)
        } finally {
            keyBytes.fill(0)
        }
    }

    fun getKeyBytes(key: ByteArray): ByteArray {
        val keyBytes: ByteArray = key.copyOf()
        return keyBytes
    }

    fun update(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray {
        var output: ByteArray? = null

        try {
            output = ByteArray(this.getOutputSizeByOperation(inputLen, false))
            val len = this.update(input, inputOffset, inputLen, output, 0)
            if (len == output.size) {
                return output
            } else {
                val copy: ByteArray = output.copyOfRange(0, len)
                if (this.decrypting) {
                    output.fill(0)
                }

                return copy
            }
        } catch (e: RuntimeException) {
            throw RuntimeException("Unexpected exception", e)
        }
    }

    fun update(input: ByteArray, inputOffset: Int, inputLen: Int, output: ByteArray, outputOffset: Int): Int {
        var input = input
        var inputOffset = inputOffset
        var inputLen = inputLen
        var outputOffset = outputOffset
        var len: Int = Math.addExact(this.buffered, inputLen)
        len -= this.minBytes
//        if (this.padding != null && this.decrypting) {
//            len -= this.blockSize
//        }

        len = if (len > 0) len - len % this.unitBytes else 0
        if (output.size - outputOffset >= len) {
            var outLen = 0
            if (len != 0) {
                if (input.contentEquals(output) && outputOffset - inputOffset < inputLen && inputOffset - outputOffset < this.buffer.size) {
//                    input = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen))
                    input = input.copyOf(inputLen)
                    inputOffset = 0
                }

                if (len <= this.buffered) {
                    if (this.decrypting) {
                        outLen = this.cipher.decrypt(this.buffer, 0, len, output, outputOffset)
                    } else {
                        outLen = this.cipher.encrypt(this.buffer, 0, len, output, outputOffset)
                    }

                    this.buffered -= len
                    if (this.buffered != 0) {
//                        System.arraycopy(this.buffer, len, this.buffer, 0, this.buffered)
                        this.buffer.copyInto(this.buffer, 0, len, len + this.buffered)
                    }
                } else {
                    var inputConsumed = len - this.buffered
                    if (this.buffered > 0) {
                        val bufferCapacity = this.buffer.size - this.buffered
                        if (bufferCapacity != 0) {
                            var temp: Int = min(bufferCapacity, inputConsumed)
                            if (this.unitBytes != this.blockSize) {
                                temp -= Math.addExact(this.buffered, temp) % this.unitBytes
                            }

//                            System.arraycopy(input, inputOffset, this.buffer, this.buffered, temp)
                            input.copyInto(buffer, this.buffered, inputOffset, temp)
                            inputOffset = Math.addExact(inputOffset, temp)
                            inputConsumed -= temp
                            inputLen -= temp
                            this.buffered = Math.addExact(this.buffered, temp)
                        }

                        if (this.decrypting) {
                            outLen = this.cipher.decrypt(this.buffer, 0, this.buffered, output, outputOffset)
                        } else {
                            outLen = this.cipher.encrypt(this.buffer, 0, this.buffered, output, outputOffset)
                            buffer.fill(0)
                        }

                        outputOffset = Math.addExact(outputOffset, outLen)
                        this.buffered = 0
                    }

                    if (inputConsumed > 0) {
                        if (this.decrypting) {
                            outLen += this.cipher.decrypt(input, inputOffset, inputConsumed, output, outputOffset)
                        } else {
                            outLen += this.cipher.encrypt(input, inputOffset, inputConsumed, output, outputOffset)
                        }

                        inputOffset += inputConsumed
                        inputLen -= inputConsumed
                    }
                }

                if (this.unitBytes != this.blockSize) {
                    if (len < this.diffBlocksize) {
                        this.diffBlocksize -= len
                    } else {
                        this.diffBlocksize = this.blockSize - (len - this.diffBlocksize) % this.blockSize
                    }
                }
            }

            if (inputLen > 0) {
//                System.arraycopy(input, inputOffset, this.buffer, this.buffered, inputLen)
                input.copyInto(buffer, buffered, inputOffset, inputOffset + inputLen)
                this.buffered = Math.addExact(this.buffered, inputLen)
            }

            return outLen
        } else {
            throw RuntimeException("Output buffer must be (at least) $len bytes long")
        }
    }

    fun doFinal(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray? {
        try {
            val output = ByteArray(this.getOutputSizeByOperation(inputLen, true))
            val finalBuf = this.prepareInputBuffer(input, inputOffset, inputLen, output, 0)
            val finalOffset = if (finalBuf.contentEquals(input)) inputOffset else 0
            val finalBufLen = if (finalBuf.contentEquals(input)) inputLen else finalBuf.size
            val outLen = this.fillOutputBuffer(finalBuf, finalOffset, output, 0, finalBufLen, input)
            this.endDoFinal()
            if (outLen < output.size) {
                val copy: ByteArray = output.copyOf()
                if (this.decrypting) {
                    output.fill(0)
                }

                return copy
            } else {
                return output
            }
        } catch (e: RuntimeException) {
            throw RuntimeException("Unexpected exception", e)
        }
    }

    fun doFinal(input: ByteArray, inputOffset: Int, inputLen: Int, output: ByteArray, outputOffset: Int): Int {
        val estOutSize = this.getOutputSizeByOperation(inputLen, true)
        val outputCapacity = this.checkOutputCapacity(output, outputOffset, estOutSize)
        var offset = outputOffset
        val finalBuf = this.prepareInputBuffer(input, inputOffset, inputLen, output, outputOffset)
        var internalOutput: ByteArray? = null
        val finalOffset = if (finalBuf.contentEquals(input)) inputOffset else 0
        val finalBufLen = if (finalBuf.contentEquals(input)) inputLen else finalBuf.size
        if (this.decrypting) {
            if (outputCapacity < estOutSize) {
                this.cipher.save()
            }

            if (outputCapacity < estOutSize) {
                internalOutput = ByteArray(estOutSize)
                offset = 0
            }
        }

        val outBuffer: ByteArray = internalOutput ?: output
        val outLen = this.fillOutputBuffer(finalBuf, finalOffset, outBuffer, offset, finalBufLen, input)
        if (this.decrypting) {
            if (outputCapacity < outLen) {
                this.cipher.restore()
                throw RuntimeException("Output buffer too short: " + outputCapacity + " bytes given, " + outLen + " bytes needed")
            }

            internalOutput?.copyInto(output, outputOffset, 0, outLen)
        }

        this.endDoFinal()
        return outLen
    }

    private fun endDoFinal() {
        this.buffered = 0
        this.diffBlocksize = this.blockSize
        if (this.cipherMode != 0) {
            this.cipher.reset()
        }
    }


    private fun prepareInputBuffer(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray?,
        outputOffset: Int
    ): ByteArray {
        val len: Int = Math.addExact(this.buffered, inputLen)
        val paddingLen = 0
        if (input.contentEquals(output) && outputOffset - inputOffset < inputLen && inputOffset - outputOffset < this.buffer.size) {

            val finalBuf = ByteArray(Math.addExact(len, paddingLen))
            if (this.buffered != 0) {
//                System.arraycopy(this.buffer, 0, finalBuf, 0, this.buffered)
                buffer.copyInto(finalBuf, 0, 0, this.buffered)
                if (!this.decrypting) {
//                    Arrays.fill(this.buffer, 0.toByte())
                    buffer.fill(0)
                }
            }

            if (inputLen != 0) {
//                System.arraycopy(input, inputOffset, finalBuf, this.buffered, inputLen)
                input.copyInto(finalBuf, this.buffered, inputOffset, inputOffset + inputLen)
            }


            return finalBuf
        } else {
            return input
        }
    }

    private fun fillOutputBuffer(
        finalBuf: ByteArray,
        finalOffset: Int,
        output: ByteArray,
        outOfs: Int,
        finalBufLen: Int,
        input: ByteArray
    ): Int {
        var var8: Int
        try {
            val len = this.finalNoPadding(finalBuf, finalOffset, output, outOfs, finalBufLen)

            var8 = len
        } finally {
            if (!this.decrypting && !finalBuf.contentEquals(input)) {
                finalBuf.fill(0)
            }
        }
        return var8
    }

    private fun checkOutputCapacity(output: ByteArray, outputOffset: Int, estOutSize: Int): Int {
        val outputCapacity = output.size - outputOffset
        val minOutSize = if (this.decrypting) estOutSize - this.blockSize else estOutSize
        if (outputCapacity >= minOutSize) {
            return outputCapacity
        } else {
            throw RuntimeException("Output buffer must be (at least) " + minOutSize + " bytes long")
        }
    }

    private fun finalNoPadding(`in`: ByteArray, inOfs: Int, out: ByteArray, outOfs: Int, len: Int): Int {
        if (len != 0) {
            val outLen: Int = if (this.decrypting) {
                this.cipher.decrypt(`in`, inOfs, len, out, outOfs)
            } else {
                this.cipher.encrypt(`in`, inOfs, len, out, outOfs)
            }
            return outLen

        } else {
            return 0
        }
    }

}

private fun Math.addExact(a: Int, b: Int): Int {
    val r = a + b
    if (a xor r and b xor r ushr 31 != 0) {
        throw ArithmeticException("integer overflow")
    }
    return r
}

private object Math