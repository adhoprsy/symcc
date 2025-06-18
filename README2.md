# 1. 安装

## 环境

具体参见build_symdict Dockerfile

重点包括：

```bash
clang-15 llvm-15-tools llvm-15-dev zlib1g-dev xz-utils libssl-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev ninja-build flex bison libz3-dev autoconf libtool ragel pkg-config

#安装rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

注意clang llvm工具等在这种方式下安装，可执行程序名一般会带版本号(clang-15 llvm-config-15)，强烈建议使用软链接或者update-alternative来创建不带版本号的引用

## afl

1. 下载

```bash
git clone https://github.com/adhoprsy/AFL.git
cd AFL
git checkout dictionary
```

2. build

```bash
# 在AFL目录下
export EDGE_INFO_OUTPUT_PATH=/tmp/edge.txt 
# 这一步是unique_id pass中输出控制流结构用的，这里先设置成一个临时位置
make
cd llvm_mode
make
```

## symcc

注意原版symcc的运行时后端文件夹结构最近变动过，如果在原版symcc上改，最好把symdict的内容直接重写上

1. 下载

```bash
# symcc
git clone https://github.com/adhoprsy/symcc.git
cd symcc
git checkout dictionary
# qsym后端 （在symcc目录下）
git clone https://github.com/adhoprsy/qsym.git runtime/qsym_backend/qsym
cd runtime/qsym_backend/qsym
git checkout dictionary
```

2. build

```bash
cd symcc
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DQSYM_BACKEND=ON -DLLVM_DIR=/usr/lib/llvm-15/cmake -DCMAKE_C_COMPILER=/usr/bin/clang-15 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-15
-DZ3_TRUST_SYSTEM_VERSION=on ../
ninja -j $(nproc)
```

## symcc 编译cpp库

[Symcc Doc C++.txt](https://github.com/eurecom-s3/symcc/blob/master/docs/C%2B%2B.txt)

在测试cpp程序时，如果希望cpp的运行时库中的代码也能参与到求解，就需要使用symcc编译cpp的运行时库libcxx，最好使用symdict中的symcc编译，（当然如果使用原版应该也行）（当然不用SymCC编译，直接用系统自带的库也能跑）

具体参见dockerfile

```docker
# Build libcxx with the SymCC compiler so we can instrument C++ code.
# RUN git clone -b llvmorg-15.0.7 --depth 1 https://github.com/llvm/llvm-project.git /llvm_source
COPY ./llvm_source /llvm_source

RUN mkdir /libcxx_native_install && mkdir /libcxx_native_build && \
    cd /libcxx_native_install \
    && export SYMCC_REGULAR_LIBCXX="yes" SYMCC_NO_SYMBOLIC_INPUT="yes" SYMCC_ENABLE_SYMDICT="no" && \
    cmake /llvm_source/llvm                                     \
      -G Ninja  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi"       \
      -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers"   \
      -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_BUILD_TYPE=Release  \
      -DCMAKE_C_COMPILER=/symcc/build/symcc                     \
      -DCMAKE_CXX_COMPILER=/symcc/build/sym++                   \
      -DHAVE_POSIX_REGEX=1 \
      -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
      -DCMAKE_INSTALL_PREFIX="/libcxx_native_build" \
      -DHAVE_STEADY_CLOCK=1 && \
    ninja distribution && \
    ninja install-distribution && \
    unset SYMCC_REGULAR_LIBCXX SYMCC_NO_SYMBOLIC_INPUT SYMCC_ENABLE_SYMDICT

 RUN cp /libcxx_native_build/include/x86_64-unknown-linux-gnu/c++/v1/* \
       /libcxx_native_build/include/c++/v1/
 RUN mv /libcxx_native_build/lib/x86_64-unknown-linux-gnu/* /libcxx_native_build/lib/
```

# 2. Fuzz

## 编译被测程序

1. 基本命令

由于afl的unique-id pass需要收集控制流边结构，所以需要先指定输出这些数据的文件路径。对于编译一个项目包含多文件的被测程序，需要指定同一个输出文件.

```bash
# afl
export EDGE_INFO_OUTPUT_PATH=/tmp/edge.txt 
afl-clang-fast -O0 -g xx.c -o xx.out

# symcc
symcc/build/symcc -O0 -g xx.c -o xx.out2
```

2. 库文件harness

fuzzbench中的程序都是库，所以需要使用harness（调用库api的一些代码）来生成二进制。编译harness要链接afl/afl++的driver程序，所以需要分别用afl和symcc编译driver，再后面编译被测库时链接过去。

afl和afl++的driver直接使用时会出现各种问题，所以我直接使用的是一个单独写的没有加各种优化的很直白的driver，具体见文件afl_driver.c

**注意：编译driver和harness时，afl的pass也会要求指定edge_info的输出，如果这部分边信息需要和被测程序的和到一起，那么需要把这里产生的edge_info.txt复制到编译每个被测程序的工作路径，后续编译被测程序的时候边信息会append到文件后面。如果不需要考虑（因为这部分driver的代码也没多少，harness的代码会在编译项目时再记录edge_info），那就随便设置一个临时路径就可以**

```bash
# afl只需要afl_driver.c
afl-clang-fast -c -g -O0 afl_driver.c o afl_driver.o
# symcc需要afl_driver.c和afl llvm_mode路径下的afl-llvm-rt.o.c
symcc/build/symcc -c -g -O0 afl/llvm_mode/afl-llvm-rt.o.c -I/afl -o afl-llvm-rt_symcc.o && \
symcc/build/symcc -c -g -O0 afl_driver.c -o afl_driver_symcc.o && \
ar r libAFL_symcc.a afl-llvm-rt_symcc.o afl_driver_symcc.o
```

fuzzbench的项目文件夹内会提供build.sh，直接设置一些环境变量然后运行即可。**注意编译前要把项目代码checkout到正确的版本，commit hash在项目文件夹下的benchmark.yml中。**

**有些项目的build脚本初始路径不是项目文件夹，而是代码文件夹，写环境变量时注意**

```bash
export EDGE_INFO_OUTPUT_PATH=$OUT/edge_info.txt

CC=/afl/afl-clang-fast CXX=/afl/afl-clang-fast++ SRC=$(pwd) OUT=$(pwd) FUZZER_LIB=/afl_driver.o ./build.sh

CC=/afl/afl-clang-fast CXX=/afl/afl-clang-fast++ SRC=$(pwd)/.. OUT=$(pwd)/.. FUZZER_LIB=/afl_driver.o ../build.sh

CC=/symcc/build/symcc CXX=/symcc/build/sym++ SRC=$(pwd) OUT=$(pwd) FUZZER_LIB=/libAFL_symcc.a ./build.sh
```

## 运行测试

建议先阅读symcc跑测试的方法。

以freetype为例：

```bash
#!/bin/bash

#关闭afl的ui
export AFL_NO_UI=1 
#容器中运行时防止不同容器绑定到同一个cpu
export AFL_NO_AFFINITY=1

timeout 12h /afl/afl-fuzz -m none -M afl -i seeds/ -o /out -- ./ftfuzzer @@ &

sleep 10
timeout 12h ~/.cargo/bin/symcc_fuzzing_helper -o /out -a afl -n symcc -- /src/benchmarks_symcc/freetype2_ftfuzzer/ftfuzzer @@ &

wait
```

*更多详情请看build_symdict下面的dockerfile*

