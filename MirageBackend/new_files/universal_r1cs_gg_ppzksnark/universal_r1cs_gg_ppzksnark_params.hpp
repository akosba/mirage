#ifndef UNIVERSAL_R1CS_GG_PPZKSNARK_PARAMS_HPP_
#define UNIVERSAL_R1CS_GG_PPZKSNARK_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

template<typename ppT>
using universal_r1cs_gg_ppzksnark_constraint_system = r1cs_constraint_system<libff::Fr<ppT> >;

} 

#endif 
