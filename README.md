# u3solve
Up366 simple solver (FOSS)

一个简单的CLI应用程序，用于直接解密Windows天学网学生客户端的题目文件并直接提取答案（不再维护）

## 使用方式
构建（初次构建需要稳定的网络环境）
```bash
./gradlew build
```

运行
```bash
./build/bin/native/releaseExecutable/U3Solve.exe
```

解析结果将会写在`./output.txt`中

## 声明
- 该项目仅作为kotlin-native的学习、探索与练手使用，不应该用作任何其它用途
- 该项目以MIT LICENSE对外开源并授权
- 本人不会再对该项目作任何更新