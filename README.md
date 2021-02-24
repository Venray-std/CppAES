CppAES
===========

使用C++编写DES加密方法，
参考
<https://blog.csdn.net/qq_28205153/article/details/55798628#t12>
<https://www.cnblogs.com/starwolf/p/3365834.html>   

使用方法
1. 首先确保安装了g++, cmake
2. 执行

```
mkdir build && cd build
cmake .. --DCMAKE_BUILD_TYPE=Debug
make
./CppAES
```
使用了google gtest，头文件依赖库分别在include, lib目录中，无须其他依赖即可使用。