# Specfense Compiler

Modified LLVM compiler with `nospec` runtime. Maintain two stacks: `regular` and `non-transient` stack by reusing SafeStack infrastructure.

Patches are applied on following base revisions:

compiler-rt: `d48e4d78293ca3a91b28c8abd77464a709263d06`
clang: `e0d61134f09e29b71a0f6eea9502a2ffcf26fcdf`
llvm: `7b129940425f14653692ae13dc7a33d551413444`
