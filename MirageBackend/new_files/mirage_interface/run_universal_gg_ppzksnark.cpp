/*
 * run_universal_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/universal_r1cs_gg_ppzksnark/universal_r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/universal_r1cs_gg_ppzksnark_pp.hpp>

int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	CircuitReader reader(argv[1], argv[2], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
   	universal_circuit_information circuit_info(reader.getNumSpec(), reader.getNumStmt(),reader.getNumWitness(), reader.getNumRnd(),
        cs.num_variables() - (reader.getNumSpec()+ reader.getNumStmt()+ reader.getNumWitness()+ reader.getNumRnd()) );

	
	libff::print_header("Universal R1CS GG-ppzkSNARK Generator");
	universal_r1cs_gg_ppzksnark_keytriple<DefaultPP> keys = universal_r1cs_gg_ppzksnark_generator<DefaultPP>(cs, circuit_info);
	printf("\n"); libff::print_indent(); libff::print_mem("after generator");


    	libff::print_header("Universal R1CS GG-ppzkSNARK Custom Specifier");
   	universal_r1cs_gg_ppzksnark_derived_key<DefaultPP> ck = customize_universal_key<DefaultPP>(keys, reader.getSpecValues());


    	libff::print_header("R1CS GG-ppzkSNARK Prover");
    	libff::print_header("R1CS GG-ppzkSNARK Prover Stage 1");

	stage1_proof_material<DefaultPP>  proof_stage1 = universal_r1cs_gg_ppzksnark_prover_stage1<DefaultPP>(keys.pk, reader.getStmtValues(), reader.getWitnessValues());
	
    	libff::print_header("R1CS GG-ppzkSNARK Prover Stage 2");

	// The prover can now compute randomness based on the first stage of the proof 
	std::vector<FieldT> rndValues = universal_r1cs_gg_ppzksnark_rnd_gen<DefaultPP>(reader.getNumRnd(), ck.gamma_spec_g1_computed + proof_stage1.comm_g1);
	printf("\n"); libff::print_indent(); libff::print_mem("after prover");	

	// Now, the prover can proceed with evaluating the rest of the circuit
	reader.eval(rndValues);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);

	int c = 0;
        const std::vector<FieldT> spec_input (full_assignment.begin(),full_assignment.begin() + reader.getNumSpec());
	c+= reader.getNumSpec();
        const std::vector<FieldT> stmt_input (full_assignment.begin() + c,full_assignment.begin() + c + reader.getNumStmt());
	c+= reader.getNumStmt();
        const std::vector<FieldT> witness_input (full_assignment.begin() + c,full_assignment.begin() + c + reader.getNumWitness());
	c+= reader.getNumWitness();
	// Regetting the random values from the assignment not needed, but just to make sure variables are ordered as expected
        const std::vector<FieldT> rnd_input (full_assignment.begin() + c,full_assignment.begin() + c + reader.getNumRnd());
	c+= reader.getNumRnd();
        const std::vector<FieldT> aux_input (full_assignment.begin() + c, full_assignment.end());

	if(!cs.is_satisfied(full_assignment)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}


    	universal_r1cs_gg_ppzksnark_proof<DefaultPP> proof= universal_r1cs_gg_ppzksnark_prover<DefaultPP>(keys.pk, ck, spec_input, stmt_input, witness_input, rnd_input, aux_input, proof_stage1, circuit_info);




    	printf("\n"); libff::print_indent(); libff::print_mem("after prover");

   	libff::print_header("Universal R1CS GG-ppzkSNARK Verifier");
    	const bool successBit = universal_r1cs_gg_ppzksnark_verifier<DefaultPP>(keys.vk, ck, stmt_input, proof, circuit_info);
   	printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    	printf("* The verification result is: %s\n", (successBit ? "PASS" : "FAIL"));

	if(!successBit){
		cout << "Verficiation failed" << endl;
		return -1;
	}	
	return 0;


}

