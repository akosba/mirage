/** 

This is an implementation of the MIRAGE's zk-SNARK for universal circuits. 
This implementation is based on the Groth16 zk-SNARK (see the paper for details)

The universal circuit is generated and specified using the java project in the repo.

* Author: Ahmed Kosba

**/

#ifndef UNIVERSAL_R1CS_GG_PPZKSNARK_HPP_
#define UNIVERSAL_R1CS_GG_PPZKSNARK_HPP_

#include <memory>
#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/universal_r1cs_gg_ppzksnark/universal_r1cs_gg_ppzksnark_params.hpp>
#include "openssl/sha.h"


namespace libsnark {


// Wires will be ordered in the following way:
// 1. The ONE input wire from libsnark
// 2. n_spec (l and l' records and operation specifiers)
// 3. n_stmt (z)
// 4. n_witness	
// 5. n_rnd randomness wires
// 6. n_aux rest of secondary inputs


/******************************** Universal Proving key ********************************/

template<typename ppT>
class universal_r1cs_gg_ppzksnark_proving_key;

template<typename ppT>
class universal_r1cs_gg_ppzksnark_proving_key {
public:
    libff::G1<ppT> alpha_g1;
    libff::G1<ppT> beta_g1;
    libff::G2<ppT> beta_g2;
    libff::G1<ppT> delta_g1;
    libff::G2<ppT> delta_g2;

    libff::G1<ppT> delta_prime_g1;

    libff::G1_vector<ppT> A_query; 
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query;
    libff::G1_vector<ppT> H_query;
    libff::G1_vector<ppT> witness_query;  
    libff::G1_vector<ppT> aux_query;      

    accumulation_vector<libff::G1<ppT>> gamma_stmt_g1;

    universal_r1cs_gg_ppzksnark_constraint_system<ppT> constraint_system;

    universal_r1cs_gg_ppzksnark_proving_key() {};
    universal_r1cs_gg_ppzksnark_proving_key<ppT>& operator=(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &other) = default;
    universal_r1cs_gg_ppzksnark_proving_key(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &other) = default;
    universal_r1cs_gg_ppzksnark_proving_key(universal_r1cs_gg_ppzksnark_proving_key<ppT> &&other) = default;
    universal_r1cs_gg_ppzksnark_proving_key(libff::G1<ppT> &&alpha_g1,
                                  libff::G1<ppT> &&beta_g1,
                                  libff::G2<ppT> &&beta_g2,
                                  libff::G1<ppT> &&delta_g1,
                                  libff::G2<ppT> &&delta_g2,
                                  libff::G1<ppT> &&delta_prime_g1,
                                  libff::G1_vector<ppT> &&A_query,
                                  knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > &&B_query,
                                  libff::G1_vector<ppT> &&H_query,
				  libff::G1_vector<ppT> &&witness_query, 
				  libff::G1_vector<ppT> &&aux_query, 
				  accumulation_vector<libff::G1<ppT>> &&gamma_stmt_g1,
                                  universal_r1cs_gg_ppzksnark_constraint_system<ppT> &&constraint_system) :
        alpha_g1(std::move(alpha_g1)),
        beta_g1(std::move(beta_g1)),
        beta_g2(std::move(beta_g2)),
        delta_g1(std::move(delta_g1)),
        delta_g2(std::move(delta_g2)),
        delta_prime_g1(std::move(delta_prime_g1)),
        A_query(std::move(A_query)),
        B_query(std::move(B_query)),
        H_query(std::move(H_query)),
        witness_query(std::move(witness_query)),
        aux_query(std::move(aux_query)),
	gamma_stmt_g1(std::move(gamma_stmt_g1)),
        constraint_system(std::move(constraint_system))
    {};

    size_t G1_size() const
    {
        return 1 + A_query.size() + B_query.domain_size() + H_query.size() + aux_query.size() + witness_query.size()
	+ gamma_stmt_g1.size();
    }

    size_t G2_size() const
    {
        return 1 + B_query.domain_size();
    }

    size_t size_in_bits() const
    {
        return (libff::size_in_bits(A_query) + B_query.size_in_bits() +
                libff::size_in_bits(H_query) + libff::size_in_bits(aux_query) + libff::size_in_bits(witness_query)+
                 1 * libff::G1<ppT>::size_in_bits() + 1 * libff::G2<ppT>::size_in_bits() + gamma_stmt_g1.size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in PK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in PK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* PK size in bits: %zu\n", this->size_in_bits());
    }


};


/******************************** Specification key ********************************/
// This is the key used by the computation specifier to set the wires that specifies the program.
// The end verifier does not need to have this loaded, so this was separated from the verification key to save space.

template<typename ppT>
class universal_r1cs_gg_ppzksnark_specification_key;

template<typename ppT>
class universal_r1cs_gg_ppzksnark_specification_key {
public:
	accumulation_vector<libff::G1<ppT> > gamma_spec_g1;
    	universal_r1cs_gg_ppzksnark_specification_key() = default;
    	universal_r1cs_gg_ppzksnark_specification_key(accumulation_vector<libff::G1<ppT> > gamma_spec_g1) :
        gamma_spec_g1(gamma_spec_g1)
    {};

    	size_t G1_size() const
    	{
		return gamma_spec_g1.size();
    	}


    	size_t size_in_bits() const
    	{
        	return gamma_spec_g1.size_in_bits();
    	}

    	void print_size() const
    	{
        	libff::print_indent(); printf("* G1 elements in Specification Key: %zu\n", this->G1_size());
        	libff::print_indent(); printf("* Specification key size in bits: %zu\n", this->size_in_bits());
    	}

};


/******************************* Universal Verification key ****************************/

template<typename ppT>
class universal_r1cs_gg_ppzksnark_verification_key;


template<typename ppT>
class universal_r1cs_gg_ppzksnark_verification_key {
public:
    libff::GT<ppT> alpha_g1_beta_g2;
    libff::G2<ppT> gamma_g2;
    libff::G2<ppT> delta_g2;
    libff::G2<ppT> delta_prime_g2;

    // accumulation_vector<libff::G1<ppT> > gamma_spec_g1; //  moved to specification key
    accumulation_vector<libff::G1<ppT> > gamma_stmt_g1; 
    accumulation_vector<libff::G1<ppT> > gamma_rnd_g1;  

    universal_r1cs_gg_ppzksnark_verification_key() = default;
    universal_r1cs_gg_ppzksnark_verification_key(const libff::GT<ppT> &alpha_g1_beta_g2,
                                       const libff::G2<ppT> &gamma_g2,
                                       const libff::G2<ppT> &delta_g2,
                                       const libff::G2<ppT> &delta_prime_g2,
				       const accumulation_vector<libff::G1<ppT> > &gamma_stmt_g1,
                                       const accumulation_vector<libff::G1<ppT> > &gamma_rnd_g1) :
        alpha_g1_beta_g2(alpha_g1_beta_g2),
        gamma_g2(gamma_g2),
        delta_g2(delta_g2),
        delta_prime_g2(delta_prime_g2),
        gamma_stmt_g1(gamma_stmt_g1),
        gamma_rnd_g1(gamma_rnd_g1)
    {};

    size_t G1_size() const
    {
        return gamma_stmt_g1.size() + gamma_rnd_g1.size();
    }

    size_t G2_size() const
    {
        return 3;
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
	// TODO: add GT size
        return (gamma_stmt_g1.size_in_bits() + gamma_rnd_g1.size_in_bits()  + 3 * libff::G2<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* VK size in bits: %zu\n", this->size_in_bits());

    }


};



template<typename ppT>
class universal_r1cs_gg_ppzksnark_derived_key;


/**
 *  This class holds customized values depending on the computation being verified.
 *  We call gamma_spec_g1_computed the custom VK key. This one does not need a trusted party to compute it.
 *  The rest of the values evaluation_At_spec and evaluation_Bt_spec are also computed during the customization part (without trusted party) and used by the prover.
 */
template<typename ppT>
class universal_r1cs_gg_ppzksnark_derived_key {
public:

    libff::G1<ppT> gamma_spec_g1_computed; // vk_spec part

	
    // Values precomputed for the prover
    libff::G1<ppT> evaluation_At_spec;
    knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>> evaluation_Bt_spec;   



    universal_r1cs_gg_ppzksnark_derived_key() = default;
    
    universal_r1cs_gg_ppzksnark_derived_key(const  libff::G1<ppT> &evaluation_At_spec, knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > &evaluation_Bt_spec , const libff::G1<ppT> &gamma_spec_g1_computed ) :
       evaluation_At_spec(evaluation_At_spec),
       evaluation_Bt_spec(evaluation_Bt_spec),	
       gamma_spec_g1_computed(gamma_spec_g1_computed)
    {}




};


/********************************** Key structure *********************************/


template<typename ppT>
class universal_r1cs_gg_ppzksnark_keytriple {
public:
    universal_r1cs_gg_ppzksnark_proving_key<ppT> pk;
    universal_r1cs_gg_ppzksnark_specification_key<ppT> spec_key;
    universal_r1cs_gg_ppzksnark_verification_key<ppT> vk;

    universal_r1cs_gg_ppzksnark_keytriple() = default;
    universal_r1cs_gg_ppzksnark_keytriple(const universal_r1cs_gg_ppzksnark_keytriple<ppT> &other) = default;

    universal_r1cs_gg_ppzksnark_keytriple(universal_r1cs_gg_ppzksnark_proving_key<ppT> &&pk,
					universal_r1cs_gg_ppzksnark_specification_key<ppT> &&spec_key,
                              universal_r1cs_gg_ppzksnark_verification_key<ppT> &&vk) :
        pk(std::move(pk)),
	spec_key(std::move(spec_key)),
        vk(std::move(vk))
    {}

     universal_r1cs_gg_ppzksnark_keytriple(universal_r1cs_gg_ppzksnark_keytriple<ppT> &&other) = default;
};


/*********************************** Stage 1  *****************************/

template<typename ppT>
class stage1_proof_material;

template<typename ppT>
class stage1_proof_material {
public:
    libff::Fr<ppT> kappa3;
    libff::G1<ppT> comm_witness_g1;     // calculated using witness values
    libff::G1<ppT> comm_stmt_g1;        // calculated using stmt values
    libff::G1<ppT> comm_g1;             // calculated using comm_witness_g1, comm_stmt_g1


    stage1_proof_material(  const libff::Fr<ppT> &kappa3,
                            const libff::G1<ppT> &comm_witness_g1,
 			    const libff::G1<ppT> &comm_stmt_g1,
                            const libff::G1<ppT> &comm_g1):
	kappa3((kappa3)),
        comm_witness_g1((comm_witness_g1)),
        comm_stmt_g1((comm_stmt_g1)),
        comm_g1((comm_g1))
    {};
};

/*********************************** Proof ***********************************/

template<typename ppT>
class universal_r1cs_gg_ppzksnark_proof;




template<typename ppT>
class universal_r1cs_gg_ppzksnark_proof {
public:
    libff::G1<ppT> g_A;
    libff::G2<ppT> g_B;
    libff::G1<ppT> g_C;
    libff::G1<ppT> g_comm_witness;

    universal_r1cs_gg_ppzksnark_proof()
    {
        // invalid proof
        this->g_A = libff::G1<ppT>::one();
        this->g_B = libff::G2<ppT>::one();
        this->g_C = libff::G1<ppT>::one();
        this->g_comm_witness = libff::G1<ppT>::one();
    }
    universal_r1cs_gg_ppzksnark_proof(const libff::G1<ppT> &g_A,
                            const libff::G2<ppT> &g_B,
                            const libff::G1<ppT> &g_C,
                            const libff::G1<ppT> &g_comm_witness) :
        g_A((g_A)),
        g_B((g_B)),
        g_C((g_C)),
        g_comm_witness((g_comm_witness))
    {};

    size_t G1_size() const
    {
        return 3;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits();
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in proof: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in proof: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Proof size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        return (g_A.is_well_formed() &&
                g_B.is_well_formed() &&
                g_C.is_well_formed() &&
		g_comm_witness.is_well_formed());
    }
};


/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for the Universal R1CS GG-ppzkSNARK.
 *
 */
template<typename ppT>
universal_r1cs_gg_ppzksnark_keytriple<ppT> universal_r1cs_gg_ppzksnark_generator(const universal_r1cs_gg_ppzksnark_constraint_system<ppT> &cs,
const universal_circuit_information &info);


template<typename ppT>
universal_r1cs_gg_ppzksnark_proof<ppT> universal_r1cs_gg_ppzksnark_prover(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &pk,
 					              const universal_r1cs_gg_ppzksnark_derived_key<ppT> &ck,
						      const std::vector<FieldT> & spec_input,
						      const std::vector<FieldT> & stmt_input,
						      const std::vector<FieldT> & witness_input,
						      const std::vector<FieldT> & rnd_input,
						      const std::vector<FieldT> & aux_input,
						      const stage1_proof_material<ppT> & stage1_proof_material,
						      const universal_circuit_information &info);


template <typename ppT>
universal_r1cs_gg_ppzksnark_derived_key<ppT> customize_universal_key(const universal_r1cs_gg_ppzksnark_keytriple<ppT> &keys, const std::vector<FieldT> &spec_input);

template <typename ppT>
stage1_proof_material<ppT>  universal_r1cs_gg_ppzksnark_prover_stage1(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &pk,
 					              const universal_r1cs_gg_ppzksnark_derived_key<ppT> &ck,
						      const std::vector<FieldT> & stmt_input,
						      const std::vector<FieldT> & witness_input);


template<typename ppT>
std::vector<FieldT> universal_r1cs_gg_ppzksnark_rnd_gen(const int &num, const libff::G1<ppT> &c);


template<typename ppT>
bool universal_r1cs_gg_ppzksnark_verifier(
					  const universal_r1cs_gg_ppzksnark_verification_key<ppT> &vk,
 					  const universal_r1cs_gg_ppzksnark_derived_key<ppT> &ck,
                                          const std::vector<FieldT> & stmt_input,
                                          const std::vector<FieldT> & rnd_input,
					  const universal_r1cs_gg_ppzksnark_proof<ppT> &proof,
					  const universal_circuit_information &info);



} 

#include <libsnark/zk_proof_systems/ppzksnark/universal_r1cs_gg_ppzksnark/universal_r1cs_gg_ppzksnark.tcc>

#endif 
