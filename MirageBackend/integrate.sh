#!/bin/bash

cp -r modified_libsnark_files/libsnark/reductions ../libsnark/libsnark/
cp -r modified_libsnark_files/libsnark/relations  ../libsnark/libsnark/
cp modified_libsnark_files/libsnark/CMakeLists.txt ../libsnark/libsnark/
cp -r new_files/mirage_interface ../libsnark/libsnark/
cp -r new_files/universal_r1cs_gg_ppzksnark ../libsnark/libsnark/zk_proof_systems/ppzksnark
cp new_files/universal_r1cs_gg_ppzksnark_pp.hpp ../libsnark/libsnark/common/default_types/




