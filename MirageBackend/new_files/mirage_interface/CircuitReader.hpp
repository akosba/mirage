/*
 * CircuitReader.hpp
 *
 *      Author: Ahmed Kosba
 */

#include "Util.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libff/common/profiling.hpp>


#include <memory.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <ctime>

#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <proc/readproc.h>
#include <libsnark/common/default_types/universal_r1cs_gg_ppzksnark_pp.hpp>

using namespace libsnark;
using namespace gadgetlib2;
using namespace std;

typedef unsigned int Wire;

typedef libff::Fr<libff::default_ec_pp> FieldT;
typedef libsnark::default_universal_r1cs_gg_ppzksnark_pp DefaultPP;
typedef ::std::shared_ptr<LinearCombination> LinearCombinationPtr;
typedef ::std::map<Wire, unsigned int> WireMap;

#define ADD_OPCODE 1
#define MUL_OPCODE 2
#define SPLIT_OPCODE 3
#define NONZEROCHECK_OPCODE 4
#define PACK_OPCODE 5
#define MULCONST_OPCODE 6
#define XOR_OPCODE 7
#define OR_OPCODE 8
#define CONSTRAINT_OPCODE 9

class universal_circuit_information;

class universal_circuit_information {
    public:
	const int n_spec = 0;        // number of inputs that define the custom circuit
	const int n_stmt = 0;        // statement size
        const int n_witness  = 0;   // number of witness inputs to the permutation
        const int n_rnd  = 0;        //  number of wires needed for the randomness
        const int n_aux  = 0;      // number of aux


   universal_circuit_information(int n_spec, int n_stmt, int n_witness, int n_rnd, int n_aux):
   n_spec(n_spec),
   n_stmt(n_stmt),
   n_witness(n_witness),
   n_rnd(n_rnd),
   n_aux(n_aux)
    {};


   universal_circuit_information& operator=(const universal_circuit_information &other) = default;
   universal_circuit_information(const universal_circuit_information &other) = default;
   universal_circuit_information(universal_circuit_information &&other) = default;
};


class CircuitReader {
public:
	CircuitReader(char* arithFilepath, char* inputsFilepath, ProtoboardPtr pb);
	int getNumSpec() {return numSpec;}
	int getNumStmt() {return numStmt;}
	int getNumWitness() {return numWitness;}
	int getNumRnd() {return numRnd;}


	void eval(std::vector<FieldT> rnds);

        std::vector<Wire> getSpecWireIds() const { return specWireIds; }
        std::vector<Wire> getStmtWireIds() const { return stmtWireIds; }
	std::vector<Wire> getWitnessWireIds() const { return witnessWireIds; }
	std::vector<Wire> getRndWireIds() const { return rndWireIds; }

        std::vector<FieldT> getSpecValues() const { return specValues; }
        std::vector<FieldT> getStmtValues() const { return stmtValues; }
        std::vector<FieldT> getWitnessValues() const { return witnessValues; }
 

private:
	ProtoboardPtr pb;
	char* arithFilepath;
	char* inputsFilepath;

	std::vector<VariablePtr> variables;
	std::vector<LinearCombinationPtr> wireLinearCombinations;
	std::vector<LinearCombinationPtr> zeroPwires;

	WireMap variableMap;
	WireMap zeropMap;

	std::vector<unsigned int> wireUseCounters;
	std::vector<FieldT> wireValues;

	std::vector<Wire> toClean;

	void firstPass();
	void secondPass();
	void readValues();

	std::vector<Wire> specWireIds;
	std::vector<Wire> stmtWireIds;
	std::vector<Wire> witnessWireIds;
	std::vector<Wire> rndWireIds;

	std::vector<FieldT> specValues;
	std::vector<FieldT> stmtValues;
	std::vector<FieldT> witnessValues;


	unsigned int numWires;

        unsigned int numSpec, numStmt, numWitness, numRnd;

	unsigned int currentVariableIdx, currentLinearCombinationIdx;

	void parseAndEval(std::vector<FieldT> rnds);
	void constructCircuit(char*);  // Second Pass:
	void mapValuesToProtoboard();

	int find(unsigned int, LinearCombinationPtr&, bool intentionToEdit = false);
	void clean();

	void addMulConstraint(char*, char*);
	void addXorConstraint(char*, char*);

	void addOrConstraint(char*, char*);
	void addAssertionConstraint(char*, char*);

	void addSplitConstraint(char*, char*, unsigned short);

	void addNonzeroCheckConstraint(char*, char*);

	void handleAddition(char*, char*);
	void handlePackOperation(char*, char*, unsigned short);
	void handleMulConst(char*, char*, char*);
	void handleMulNegConst(char*, char*, char*);

};

