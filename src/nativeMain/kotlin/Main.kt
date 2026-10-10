@file:OptIn(ExperimentalForeignApi::class)

import aes.AESCipherCBC
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.serialization.json.*
import me.archinamon.fileio.*
import platform.windows.*
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.math.min
import kotlin.time.DurationUnit
import kotlin.time.toDuration


private const val STEP = "    "
private const val SHOULD_WARP = false

private var MAXIMUM_ANSWER_LENGTH = -1

private val HTML_LABEL = Regex("<.*?>")
private val json = Json {
    prettyPrint = true
}

fun main(args: Array<String>) {
    memScoped {
        if (args.isNotEmpty()) {
            var argsPtr = 0
            while (argsPtr < args.size) {
                when (args[argsPtr]) {
                    "-h", "--help" -> {
                        println("Usage:")
                        println("  -h, --help                  Show this help message and exit.")
//                        println("  -d, --dir <path>            Specify the directory where the files are located.")
//                        println("  -s, --serial <number>       Specify the serial number of the file to be parsed.")
                        println("  -l, --max-length <number>   Specify the maximum length of the answer to be displayed.")
                        return
                    }
                    "-l", "--max-length" -> {
                        argsPtr++
                        MAXIMUM_ANSWER_LENGTH = args[argsPtr].toInt()
                        argsPtr++
                    }
                }
            }
        }
        val file = File("up366solver-cache")
        val u3path: String
        if (file.exists() && file.isFile()) {
            u3path = file.readText()
        } else {
            print("Enter Up366StudentFiles path (default in C:\\Up366StudentFiles):")

            u3path = (readlnOrNull() ?: "").ifEmpty { "C:\\Up366StudentFiles" }
            file.createNewFile()
            file.writeText(u3path)
        }

        val fileDir = u3path.trim(' ', '"')

        askWhichIn(fileDir)
    }
}

private fun askWhichIn(fileDir: String) {
    val file = File(fileDir)
    if (!file.exists()) {
        println("File not exists")
        return
    }

    println("User dir: ${file.getAbsolutePath()}")
    println("Please select the date and enter the corresponding serial number in order to parse it.")
    val fileList = ArrayList<File>()
    simpleWalkFileTree(file, {
        if (it.isFile()) {
            val name = it.getName()
            if (name == "page1.js.u3enc") {
                fileList.add(it)
            }
        }
    })
    fileList.sortBy { lastModified(it.getPath()) }
    fileList.reverse()
    val time: Long = memScoped {
        val fileTime = alloc<FILETIME>()
        GetSystemTimeAsFileTime(fileTime.ptr)
        val time = fileTime.dwLowDateTime.toLong() or (fileTime.dwHighDateTime.toLong() shl 32)
        (time / 10000) -  11644473600000
    }
    println("Time: $time")
    for (i in fileList.indices) {
        val file = fileList[i]
        val lastModified = lastModified(file.getPath())
        val dif = time - lastModified
        println("${i + 1}. ${representationFormat(dif)}. (${file.getAbsolutePath()})")
    }
    print("Enter serial number:")
    val serial = readln().toInt() - 1
    if (serial < 0 || serial >= fileList.size) {
        println("Invalid serial number")
        return
    }

    parseFile(fileList[serial])
}

private fun simpleWalkFileTree(file: File, action: (File) -> Unit, recursive: Boolean = true) {
    if (file.isFile()) {
        action(file)
    } else {
        for (item in file.listFiles()) {
            simpleWalkFileTree(item, action, recursive)
        }
    }
}

private val key = byteArrayOf(64, -112, 77, -120, 25, -107, -25, -109, -61, -83, -20, 50, -99, -19, -58, -80)
@OptIn(ExperimentalEncodingApi::class, ExperimentalStdlibApi::class)
private fun parseFile(file: File) {
    val encrypted = file.readBytes()

//    var signBytes = encrypted.copyOfRange(0, 16)
//    println("sgn: ${signBytes.toHexString(HexFormat.UpperCase)}")

    val decrypted = decryptAesCbc(encrypted, key)

//    signBytes = decrypted.copyOfRange(0, 16)
//    println("decrypted sgn: ${signBytes.toHexString(HexFormat.UpperCase)}")

    val text = findJsonScope(decrypted.decodeToString())
//    println(":\n$text")
//    val f = File("${file.nameWithoutExtension}.dec.txt")
//    if (f.exists()) f.delete()
//    f.createNewFile()
//    f.writeText(text)
    val element = json.parseToJsonElement(text).jsonObject

    val sb = StringBuilder()
    try {
        decPracticeMode(element, sb)
    } catch (e: Exception) {
        println("using exam mode caused by ${e::class.qualifiedName}")
        decExamMode(element, sb)
    }
    println(sb)
    val f2 = File("output.txt")
    if (f2.exists()) f2.delete()
    f2.createNewFile()
    f2.writeText(sb.toString())
}

private fun decPracticeMode(json: JsonObject, sb: StringBuilder) {
    val elements = json["sliders"]!!.jsonArray
    for (element in elements) {
        rekFmtQuestionInfo(element.jsonObject, sb)
    }
}

private fun decExamMode(input: JsonObject, sb: StringBuilder) {
    readQuestionList(input, sb)
}

private fun rekFmtQuestionInfo(info: JsonObject, sb: StringBuilder) {
    val title = info["title"]!!.jsonPrimitive.content
    val displayType = info["displayType"]!!.jsonPrimitive.content
    val builder = StringBuilder()
    builder.append("$title-$displayType\n")
    readQuestionList(info, builder)
    sb.append(builder).append("\n")
}

private fun readQuestionList(info: JsonObject, out: StringBuilder) {
    val questionList = info["questionList"]!!.jsonArray
    for (question in questionList) {
        val smallPart = question.jsonObject
        // String questionText = HTML_LABEL.matcher(smallPart.getString("question_text")).replaceAll("");
        val questionText = HTML_LABEL.replace(smallPart["question_text"]!!.jsonPrimitive.content, "")

        out.append(STEP).append(wrap(STEP + STEP, questionText, 86)).append("\n")
        /*
        * JSONArray recordSpeaks = smallPart.getJSONArray("record_speak");
            if (!allowEmptySpeak && recordSpeaks == null) {
                continue;
            }
            if (recordSpeaks != null) {
                for (int j = 0; j < recordSpeaks.size(); j++) {
                    JSONObject recordSpeak = recordSpeaks.getJSONObject(j);
                    boolean safe = "0".equals(recordSpeak.getString("fake")) && "1".equals(recordSpeak.getString("work"));
                    out.append(step).append(step);
                    if (!safe) out.append("(!) ");
                    String content = validateNoRepeat(recordSpeak.getString("content"));
                    out.append(wrap(step + step + step, content, 80)).append("\n");
                }
            }
            out.append("\n");
           */
        smallPart["record_speak"]?.jsonArray?.let {
            for (j in it.indices) {
                if (MAXIMUM_ANSWER_LENGTH > 0 && j >= MAXIMUM_ANSWER_LENGTH) break
                val recordSpeak = it[j].jsonObject
                val safe = recordSpeak["fake"]?.jsonPrimitive?.content == "0" && recordSpeak["work"]?.jsonPrimitive?.content == "1"
                out.append(STEP).append(STEP)
                if (!safe) out.append("(!) ")
                val content = recordSpeak["content"]!!.jsonPrimitive.content
                out.append(wrap(STEP + STEP + STEP, content, 80)).append("\n")
            }
        }
    }
}

private fun decryptAesCbc(input: ByteArray, key: ByteArray): ByteArray {
    val aes = AESCipherCBC()
    aes.init(true, key, key)
    var decrypted = aes.doFinal(input, 0, input.size)!!
    var ind = 0
    while (ind < decrypted.size) {
        if (decrypted[ind].toInt() and 0xFF == 0) ind++
        else break
    }
    decrypted = decrypted.copyOfRange(ind, decrypted.size)

    if (decrypted.isNotEmpty()) {
        ind = decrypted.size - 1
        while (ind >= 0) {
            if (decrypted[ind].toInt() and 0xFF == 0) ind--
            else break
        }
        decrypted = decrypted.copyOfRange(0, ind + 1)
    }
    return decrypted
}

private fun findJsonScope(text: String): String {
    return text.substring(text.indexOf('{'), text.lastIndexOf('}') + 1)
}

private fun lastModified(pathname: String): Long {
    val handle = CreateFileW(
        pathname,
        GENERIC_READ,
        (FILE_SHARE_DELETE or FILE_SHARE_READ or FILE_SHARE_WRITE).toUInt(),
        null,
        OPEN_EXISTING.toUInt(),
        FILE_ATTRIBUTE_NORMAL.toUInt(),
        null
    )
    if (handle == INVALID_HANDLE_VALUE) {
        return 0L
    }

    return try {
        memScoped {
            val ft = alloc<_FILETIME>()
            val result = GetFileTime(handle, null, null, ft.ptr)
            if (result == TRUE) {
                val time = (ft.dwHighDateTime.toLong() shl 32) or ft.dwLowDateTime.toLong()
                (time / 10000) - 11644473600000
            } else 0L
        }
    } finally {
        CloseHandle(handle)
    }
}

fun wrap(linePrefix: String?, text: String?, width: Int): String? {
    if (text == null || text.isEmpty() || width <= 0 || !SHOULD_WARP) {
        if (text != null) {
            return text.trim()
        }
        return null
    }

    val result = StringBuilder()
    val words = text.trim().split(" ")
    val line = StringBuilder()

    for (word in words) {
        if (line.length + word.length > width) {
            // 如果当前行已有内容，则换行
            if (!line.isEmpty()) {
                result.append(line.toString().trim()).append("\n").append(linePrefix)
                line.setLength(0)
                //                    line.append(linePrefix);
            }
            // 如果单个单词超过宽度限制，需要拆分
            if (word.length > width) {
                var i = 0
                while (i < word.length) {
                    val end: Int = min(i + width, word.length)
                    result.append(word.substring(i, end).trim()).append("\n").append(linePrefix)
                    i += width
                }
                continue
            }
        }
        if (word.contains("\n")) {
            val lines = word.split("\n")
            for (i in lines.indices) {
            }
        }
        line.append(word).append(" ")
    }


    // 添加最后一行
    if (!line.isEmpty()) {
        result.append(line.toString().trim())
    }

    return result.toString().replace("\n", "\n" + linePrefix)
}

private fun representationFormat(deltaMS: Long): String {
    val duration = deltaMS.toDuration(DurationUnit.MILLISECONDS)
    return when {
        duration.inWholeDays > 0 -> {
            val days = duration.inWholeDays
            "$days day${if (days > 1) "s" else ""} ago"
        }
        duration.inWholeHours > 0 -> {
            val hours = duration.inWholeHours
            "$hours hour${if (hours > 1) "s" else ""} ago"
        }
        duration.inWholeMinutes > 0 -> {
            val minutes = duration.inWholeMinutes
            "$minutes minute${if (minutes > 1) "s" else ""} ago"
        }
        else -> {
            val seconds = duration.inWholeSeconds
            "$seconds second${if (seconds > 1) "s" else ""} ago"
        }
    }
}