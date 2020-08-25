/** 

This is an implementation of the MIRAGE's zk-SNARK for universal circuits. 
This implementation is a modification of Groth16 zk-SNARK implemented in libsnark.

The universal circuit is generated and specified using the java project in the repo.

* @author     Ahmed Kosba

**/

#ifndef UNIVERSAL_R1CS_GG_PPZKSNARK_TCC_
#define UNIVERSAL_R1CS_GG_PPZKSNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {

template <typename ppT>
universal_r1cs_gg_ppzksnark_keytriple<ppT> universal_r1cs_gg_ppzksnark_generator(const universal_r1cs_gg_ppzksnark_constraint_system<ppT> &r1cs, const
universal_circuit_information &info)
{
    libff::enter_block("Call to universal r1cs_gg_ppzksnark_generator");

    // This to reduce the effort of the B-query
    universal_r1cs_gg_ppzksnark_constraint_system<ppT> r1cs_copy(r1cs);

    libff::bit_vector expensiveG2(r1cs.num_variables() + 1, false), freeG2(r1cs.num_variables() + 1, false);
    
    freeG2[0] = true;
    for(int i = 0; i < r1cs.num_variables() ; i++){
	if(i < info.n_spec || (i >= info.n_spec + info.n_stmt + info.n_witness && i <  info.n_spec + info.n_stmt + info.n_witness + info.n_rnd)){
    		freeG2[i+1] = true;
	}
	if(i >= info.n_spec && i < info.n_spec + info.n_stmt + info.n_witness){
    		expensiveG2[i+1] = true;
	}
    }

    r1cs_copy.swap_AB_if_beneficial(expensiveG2, freeG2);

    /* Generate secret randomness */
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta_prime = libff::Fr<ppT>::random_element();


    const libff::Fr<ppT> gamma_inverse = gamma.inverse();
    const libff::Fr<ppT> delta_inverse = delta.inverse();
    const libff::Fr<ppT> delta_prime_inverse = delta_prime.inverse();


    qap_instance_evaluation<libff::Fr<ppT> > qap = r1cs_to_qap_instance_map_with_evaluation_no_input_constraints(r1cs_copy, t);

    libff::print_indent(); printf("* QAP number of variables: %zu\n", qap.num_variables());
    libff::print_indent(); printf("* QAP pre degree: %zu\n", r1cs_copy.constraints.size());
    libff::print_indent(); printf("* QAP degree: %zu\n", qap.degree());
    libff::print_indent(); printf("* QAP number of input variables: %zu\n", qap.num_inputs());

    libff::enter_block("Compute query densities");
    size_t non_zero_At = 0;
    size_t non_zero_Bt = 0;
    for (size_t i = 0; i < qap.num_variables() + 1; ++i)
    {
        if (!qap.At[i].is_zero())
        {
            ++non_zero_At;
        }
        if (!qap.Bt[i].is_zero())
        {
            ++non_zero_Bt;
        }
    }
    libff::leave_block("Compute query densities");


    libff::Fr_vector<ppT> At = std::move(qap.At);
    libff::Fr_vector<ppT> Bt = std::move(qap.Bt);
    libff::Fr_vector<ppT> Ct = std::move(qap.Ct);
    libff::Fr_vector<ppT> Ht = std::move(qap.Ht);


    libff::enter_block("Compute gamma components for specification and verification keys");
    libff::Fr_vector<ppT> gamma_spec;
    libff::Fr_vector<ppT> gamma_stmt;
    libff::Fr_vector<ppT> gamma_rnd;


    gamma_spec.reserve(info.n_spec);
    gamma_stmt.reserve(info.n_stmt);
    gamma_rnd.reserve(info.n_rnd);


    const libff::Fr<ppT> gamma_0 = (beta * At[0] + alpha * Bt[0] + Ct[0]) * gamma_inverse;
    for (size_t i = 1; i < info.n_spec+1; ++i)
    {
        gamma_spec.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
    }
    for (size_t i = info.n_spec+1; i < info.n_spec+info.n_stmt+1; ++i)
    {
        gamma_stmt.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
    }
    for (size_t i = info.n_spec + info.n_stmt + info.n_witness +1; i < info.n_spec + info.n_stmt + info.n_witness + info.n_rnd +1; ++i)
    {
        gamma_rnd.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
    }


    libff::leave_block("Compute gamma components for specification and verification keys");


    libff::enter_block("Compute witness and aux query for proving key");


    libff::Fr_vector<ppT> witness_t;
    witness_t.reserve(info.n_witness);
    libff::Fr_vector<ppT> aux_t;
    aux_t.reserve(info.n_aux);

    const size_t offsetW = info.n_spec + info.n_stmt + 1;
    for (size_t i = 0; i < info.n_witness; ++i)
    {
         witness_t.emplace_back((beta * At[offsetW  + i] + alpha * Bt[offsetW  + i] + Ct[offsetW  + i]) * delta_prime_inverse);
    }


    const size_t offsetAux = info.n_spec + info.n_rnd + info.n_stmt + 1 + info.n_witness;
    for (size_t i = 0; i < info.n_aux; ++i)
    {
         aux_t.emplace_back((beta * At[offsetAux  + i] + alpha * Bt[offsetAux + i] + Ct[offsetAux + i]) * delta_inverse);
    }



    libff::leave_block("Compute witness and aux query for proving key");

    /**
     * Comment left from libsnark: Note that H for Groth's proof system is degree d-2, but the QAP
     * reduction returns coefficients for degree d polynomial H (in
     * style of PGHR-type proof systems)
     */
    Ht.resize(Ht.size() - 2);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Generating G1 MSM window table");
    const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
    const size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables();
    const size_t g1_scalar_size = libff::Fr<ppT>::size_in_bits();
    const size_t g1_window_size = libff::get_exp_window_size<libff::G1<ppT> >(g1_scalar_count);

    libff::print_indent(); printf("* G1 window: %zu\n", g1_window_size);
    libff::window_table<libff::G1<ppT> > g1_table = libff::get_window_table(g1_scalar_size, g1_window_size, g1_generator);
    libff::leave_block("Generating G1 MSM window table");

    libff::enter_block("Generating G2 MSM window table");
    const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();
    const size_t g2_scalar_count = non_zero_Bt;
    const size_t g2_scalar_size = libff::Fr<ppT>::size_in_bits();
    size_t g2_window_size = libff::get_exp_window_size<libff::G2<ppT> >(g2_scalar_count);

    libff::print_indent(); printf("* G2 window: %zu\n", g2_window_size);
    libff::window_table<libff::G2<ppT> > g2_table = libff::get_window_table(g2_scalar_size, g2_window_size, G2_gen);
    libff::leave_block("Generating G2 MSM window table");

    libff::enter_block("Generate proving key");
    libff::G1<ppT> alpha_g1 = alpha * g1_generator;
    libff::G1<ppT> beta_g1 = beta * g1_generator;
    libff::G2<ppT> beta_g2 = beta * G2_gen;
    libff::G1<ppT> delta_g1 = delta * g1_generator;
    libff::G2<ppT> delta_g2 = delta * G2_gen;
    libff::G1<ppT> delta_prime_g1 = delta_prime*g1_generator;
    libff::G2<ppT> delta_prime_g2 = delta_prime*G2_gen;

    libff::enter_block("Generate queries");
    libff::enter_block("Compute the A-query", false);
    libff::G1_vector<ppT> A_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(A_query);
#endif
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g2_window_size, g1_window_size, g2_table, g1_table, libff::Fr<ppT>::one(), libff::Fr<ppT>::one(), Bt, chunks);

    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute the witness and aux query", false);


    libff::G1_vector<ppT> witness_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, witness_t);
    libff::G1_vector<ppT> aux_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, aux_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(witness_query);
    libff::batch_to_special<libff::G1<ppT> >(aux_query);
#endif
    libff::leave_block("Compute the witness and aux query", false);
    libff::leave_block("Generate queries");

    libff::leave_block("Generate proving key");

    libff::enter_block("Generate specification and verification keys");
    libff::GT<ppT> alpha_g1_beta_g2 = ppT::reduced_pairing(alpha_g1, beta_g2);
    libff::G2<ppT> gamma_g2 = gamma * G2_gen;


    libff::G1<ppT> gamma_0_g1 = gamma_0 * g1_generator;

    libff::G1_vector<ppT> gamma_spec_g1_values = batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_spec);
    libff::G1_vector<ppT> gamma_stmt_g1_values = batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_stmt);
    libff::G1_vector<ppT> gamma_rnd_g1_values = batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_rnd);

    libff::leave_block("Generate specification and verification keys");


    accumulation_vector<libff::G1<ppT>> gamma_spec_g1(std::move(gamma_0_g1), std::move(gamma_spec_g1_values));
    accumulation_vector<libff::G1<ppT>> gamma_stmt_g1(std::move(gamma_stmt_g1_values));
    accumulation_vector<libff::G1<ppT>> gamma_rnd_g1(std::move(gamma_rnd_g1_values));

    universal_r1cs_gg_ppzksnark_verification_key<ppT> vk = universal_r1cs_gg_ppzksnark_verification_key<ppT>(alpha_g1_beta_g2,
                                                                                         gamma_g2,
                                                                                         delta_g2,
                                                                                         delta_prime_g2,
                                                                                         gamma_stmt_g1,
                                                                                         gamma_rnd_g1);

    universal_r1cs_gg_ppzksnark_specification_key<ppT> spec_key = universal_r1cs_gg_ppzksnark_specification_key<ppT>(gamma_spec_g1);

    universal_r1cs_gg_ppzksnark_proving_key<ppT> pk = universal_r1cs_gg_ppzksnark_proving_key<ppT>(std::move(alpha_g1),
                                                                               std::move(beta_g1),
                                                                               std::move(beta_g2),
                                                                               std::move(delta_g1),
                                                                               std::move(delta_g2),
                                                                               std::move(delta_prime_g1),
                                                                               std::move(A_query),
                                                                               std::move(B_query),
                                                                               std::move(H_query),
                                                                               std::move(witness_query),
                                                                               std::move(aux_query),
									       std::move(gamma_stmt_g1),	
                                                                               std::move(r1cs_copy));

    pk.print_size();
    spec_key.print_size();	
    vk.print_size();



    libff::leave_block("Call to universal r1cs_gg_ppzksnark_generator");
    return universal_r1cs_gg_ppzksnark_keytriple<ppT>(std::move(pk), std::move(spec_key), std::move(vk));
}




template <typename ppT>
stage1_proof_material<ppT>  universal_r1cs_gg_ppzksnark_prover_stage1(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &pk,
						      const std::vector<FieldT> & stmt_input,
						      const std::vector<FieldT> & witness_input)
{

     libff::Fr<ppT> kappa3 = libff::Fr<ppT>::random_element();
#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); 
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute evaluation to Witness-query", false);

    libff::Fr_vector<ppT> const_padded_assignment;
    const_padded_assignment.insert(const_padded_assignment.end(), witness_input.begin(), witness_input.end());

    libff::G1<ppT> evaluation_witnesst = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.witness_query.begin(),
        pk.witness_query.end(),
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + witness_input.size(),
        chunks);
    libff::leave_block("Compute evaluation to Witness-query", false);


   libff::G1<ppT> comm_witness_g1 = kappa3 * pk.delta_g1 + evaluation_witnesst ;

    libff::enter_block("Accumulate Stmt");
    const accumulation_vector<libff::G1<ppT> > accumulated_stmt = pk.gamma_stmt_g1.template accumulate_chunk<libff::Fr<ppT> >(stmt_input.begin(), stmt_input.end(), 0);
     libff::G1<ppT> comm_stmt_g1 = accumulated_stmt.first;
    libff::leave_block("Accumulate Stmt");

    libff::enter_block("Calculate commitment");
     libff::G1<ppT> comm_g1 = comm_witness_g1  + comm_stmt_g1;
    libff::leave_block("Calculate commitment");

    stage1_proof_material<ppT> proof_stage_1 = stage1_proof_material<ppT>(kappa3, comm_witness_g1, comm_stmt_g1, comm_g1);

    return proof_stage_1;
}







template <typename ppT>
universal_r1cs_gg_ppzksnark_proof<ppT> universal_r1cs_gg_ppzksnark_prover(const universal_r1cs_gg_ppzksnark_proving_key<ppT> &pk,
 					              const universal_r1cs_gg_ppzksnark_derived_key<ppT> &ck,
						      const std::vector<FieldT> & spec_input,
						      const std::vector<FieldT> & stmt_input,
						      const std::vector<FieldT> & witness_input,
						      const std::vector<FieldT> & rnd_input,
						      const std::vector<FieldT> & aux_input,
						      const stage1_proof_material<ppT> & stage1_proof_material,
						      const universal_circuit_information &info)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_prover");




    r1cs_variable_assignment<FieldT> full_variable_assignment = spec_input;
    full_variable_assignment.insert(full_variable_assignment.end(), stmt_input.begin(), stmt_input.end());
    full_variable_assignment.insert(full_variable_assignment.end(), witness_input.begin(), witness_input.end());
    full_variable_assignment.insert(full_variable_assignment.end(), rnd_input.begin(), rnd_input.end());
    full_variable_assignment.insert(full_variable_assignment.end(), aux_input.begin(), aux_input.end());



    libff::enter_block("Compute the polynomial H");
    const qap_witness<libff::Fr<ppT> > qap_wit = r1cs_to_qap_witness_map_no_input_constraints(pk.constraint_system, full_variable_assignment, libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());

    assert(!qap_wit.coefficients_for_H[qap_wit.degree()-2].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()-1].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()].is_zero());
    libff::leave_block("Compute the polynomial H");

    // select random values for zero knowledge
    const libff::Fr<ppT> kappa1 = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> kappa2 = libff::Fr<ppT>::random_element();


#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); 
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute the proof");

    int idx_displacement = spec_input.size() + 1;

    libff::enter_block("Compute evaluation to A-query", false);

    libff::Fr_vector<ppT> const_padded_assignment(1, libff::Fr<ppT>::one());
    const_padded_assignment.insert(const_padded_assignment.end(), qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.end());

    libff::G1<ppT> evaluation_At = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.A_query.begin() +idx_displacement,
        pk.A_query.begin() + qap_wit.num_variables() + 1,
        const_padded_assignment.begin() + idx_displacement,
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to A-query", false);

    libff::enter_block("Compute evaluation to B-query", false);
    knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > evaluation_Bt = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                                                                           libff::G1<ppT>,
                                                                                                           libff::Fr<ppT>,
                                                                                                           libff::multi_exp_method_BDLO12>(
        pk.B_query,
        0 + idx_displacement,
        qap_wit.num_variables() + 1,
        const_padded_assignment.begin() + idx_displacement,
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to B-query", false);



    libff::enter_block("Compute evaluation to H-query", false);
    libff::G1<ppT> evaluation_Ht = libff::multi_exp<libff::G1<ppT>,
                                                    libff::Fr<ppT>,
                                                    libff::multi_exp_method_BDLO12>(
        pk.H_query.begin(),
        pk.H_query.begin() + (qap_wit.degree() - 1),
        qap_wit.coefficients_for_H.begin(),
        qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1),
        chunks);
    libff::leave_block("Compute evaluation to H-query", false);

    libff::enter_block("Compute evaluation to Aux-query", false);
    libff::G1<ppT> evaluation_auxt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.aux_query.begin(),
        pk.aux_query.end(),
        const_padded_assignment.begin() +  info.n_stmt + info.n_spec + info.n_witness + info.n_rnd + 1,
        const_padded_assignment.begin() +  info.n_stmt + info.n_spec + info.n_witness + info.n_rnd + info.n_aux + 1,
        chunks);
    libff::leave_block("Compute evaluation to Aux-query", false);



    libff::G1<ppT> g1_A = pk.alpha_g1 + evaluation_At + ck.evaluation_At_spec + kappa1 * pk.delta_g1;

    libff::G1<ppT> g1_B = pk.beta_g1 + evaluation_Bt.h + ck.evaluation_Bt_spec.h + kappa2 * pk.delta_g1;
    libff::G2<ppT> g2_B = pk.beta_g2 + evaluation_Bt.g + ck.evaluation_Bt_spec.g + kappa2 * pk.delta_g2;


    libff::G1<ppT> g1_C = evaluation_Ht + evaluation_auxt + kappa2 *  g1_A + kappa1 * g1_B - (kappa1 * kappa2) * pk.delta_g1  - (stage1_proof_material.kappa3) * pk.delta_prime_g1;



    libff::leave_block("Compute the proof");

    libff::leave_block("Call to r1cs_gg_ppzksnark_prover");

    universal_r1cs_gg_ppzksnark_proof<ppT> proof = universal_r1cs_gg_ppzksnark_proof<ppT>(g1_A, g2_B, g1_C, stage1_proof_material.comm_witness_g1);
    proof.print_size();

    return proof;
}









template <typename ppT>
universal_r1cs_gg_ppzksnark_derived_key<ppT> customize_universal_key(universal_r1cs_gg_ppzksnark_keytriple<ppT> &keys, const std::vector<FieldT> &spec_input)
{

    libff::enter_block("Call to customize universal key");

    libff::enter_block("Accumulate Spec");
    const accumulation_vector<libff::G1<ppT> > accumulated_spec = keys.spec_key.gamma_spec_g1.template accumulate_chunk<libff::Fr<ppT> >(spec_input.begin(), spec_input.end(), 0);
    const libff::G1<ppT> &gamma_spec_g1_computed  = accumulated_spec.first;
    libff::leave_block("Accumulate Spec");


#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); 
#else
    const size_t chunks = 1;
#endif


    libff::Fr_vector<ppT> const_padded_assignment(1, libff::Fr<ppT>::one());
    const_padded_assignment.insert(const_padded_assignment.end(), spec_input.begin(), spec_input.end());


    libff::enter_block("Compute evaluation to A-query (spec) ", false);
    libff::G1<ppT> evaluation_At_spec = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        keys.pk.A_query.begin(),
        keys.pk.A_query.begin() + spec_input.size() + 1,
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + spec_input.size()  + 1,
        chunks);
    libff::leave_block("Compute evaluation to A-query (spec) ", false);

    libff::enter_block("Compute evaluation to B-query (spec)", false);
    knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > evaluation_Bt_spec = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                                                                           libff::G1<ppT>,
                                                                                                           libff::Fr<ppT>,
                                                                                                           libff::multi_exp_method_BDLO12>(
        keys.pk.B_query,
        0,
        spec_input.size() + 1,
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + spec_input.size() + 1,
        chunks);
    libff::leave_block("Compute evaluation to B-query (spec)", false);


     universal_r1cs_gg_ppzksnark_derived_key<ppT> ck(evaluation_At_spec, evaluation_Bt_spec , gamma_spec_g1_computed);

     libff::leave_block("Call to customize universal key");

     return ck;

}


template<typename ppT>
std::vector<FieldT> universal_r1cs_gg_ppzksnark_rnd_gen(const int &num, const libff::G1<ppT> &c){
     	

	std::vector<FieldT> rndValues;

	for(int i = 0; i < num; i++){
		std::ostringstream stream;
		stream << i;
		stream << c ; 
     		std::string str =  stream.str();
     		const char* string = str.c_str();
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, string, strlen(string));
		SHA256_Final(hash, &sha256);

		FieldT rnd(0);
    		FieldT weight(1);
    		FieldT step(256);

		for(int i = 0; i < SHA256_DIGEST_LENGTH-3; i++) {
			rnd = rnd + FieldT((unsigned int)hash[i])*weight;
			weight = weight * step;
		}
		rndValues.push_back(rnd);
	}
	return rndValues;

}



template<typename ppT>
bool universal_r1cs_gg_ppzksnark_verifier(
					  const universal_r1cs_gg_ppzksnark_verification_key<ppT> &vk,
					  const universal_r1cs_gg_ppzksnark_derived_key<ppT> &ck,
                                          const std::vector<FieldT> & stmt_input,
					  const universal_r1cs_gg_ppzksnark_proof<ppT> &proof,
					  const universal_circuit_information &info)
{

    libff::enter_block("Call to universal_r1cs_gg_ppzksnark_verifier");
    libff::enter_block("Accumulate Stmt");
    const accumulation_vector<libff::G1<ppT> > accumulated_stmt = vk.gamma_stmt_g1.template accumulate_chunk<libff::Fr<ppT> >(stmt_input.begin(), stmt_input.end(), 0);
    const libff::G1<ppT> &gamma_stmt_g1_computed = accumulated_stmt.first;
    libff::leave_block("Accumulate Stmt");

    libff::enter_block("Compute randomness input");
    const libff::G1<ppT> comm_g1 = proof.g_comm_witness + gamma_stmt_g1_computed;
    std::vector<FieldT> rnd_input = universal_r1cs_gg_ppzksnark_rnd_gen<ppT>(info.n_rnd, comm_g1 + ck.gamma_spec_g1_computed);
    libff::leave_block("Compute randomness input");

    libff::enter_block("Accumulate Rnd");
    const accumulation_vector<libff::G1<ppT> > accumulated_rnd = vk.gamma_rnd_g1.template accumulate_chunk<libff::Fr<ppT> >(rnd_input.begin(), rnd_input.end(), 0);
    const libff::G1<ppT> &gamma_rnd_g1_computed = accumulated_rnd.first;
    libff::leave_block("Accumulate Rnd");

     const libff::G1<ppT> stmt_g1 = gamma_rnd_g1_computed + gamma_stmt_g1_computed + ck.gamma_spec_g1_computed;
     const libff::G1_precomp<ppT> proof_g_A_precomp = ppT::precompute_G1(proof.g_A);
     const libff::G2_precomp<ppT> proof_g_B_precomp = ppT::precompute_G2(proof.g_B);
     const libff::G1_precomp<ppT> proof_g_C_precomp = ppT::precompute_G1(proof.g_C);
     const libff::G1_precomp<ppT> proof_g_comm_witness_precomp = ppT::precompute_G1(-proof.g_comm_witness);
     const libff::G1_precomp<ppT> stmt_precomp = ppT::precompute_G1(stmt_g1);
     const libff::G2_precomp<ppT> vk_gamma_g2_precomp = ppT::precompute_G2(vk.gamma_g2);   
     const libff::G2_precomp<ppT> vk_delta_g2_precomp = ppT::precompute_G2(vk.delta_g2);   
     const libff::G2_precomp<ppT> vk_delta_prime_g2_precomp = ppT::precompute_G2(vk.delta_prime_g2);   

    const libff::Fqk<ppT> QAP_a_b = ppT::double_miller_loop(proof_g_A_precomp,  proof_g_B_precomp, proof_g_comm_witness_precomp, vk_delta_prime_g2_precomp );
    const libff::Fqk<ppT> QAP_stmt_c = ppT::double_miller_loop(
        stmt_precomp, vk_gamma_g2_precomp ,
        proof_g_C_precomp, vk_delta_g2_precomp);


    const libff::GT<ppT> tmp1 = ppT::final_exponentiation(QAP_a_b * QAP_stmt_c.unitary_inverse());
    const libff::GT<ppT> tmp2 =  vk.alpha_g1_beta_g2 ; 

    bool result = true;
    if (tmp1 != tmp2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("Verification failed.\n");
        }
        result = false;
    }


    libff::leave_block("Call to universal_r1cs_gg_ppzksnark_verifier");
    return result;
}

} 
#endif 
